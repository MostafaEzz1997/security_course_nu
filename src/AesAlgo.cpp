#include "AesAlgo.hpp"


// Nk = 4: Number of 32-bit words in the key for AES-128
// Nr = 10: Number of rounds for AES-128
AesAlgo::AesAlgo(bool gf_enabled, bool padding_enabled): 
	Nk(4), 
	Nr(10), 
	_gf_enabled(gf_enabled), 
	_padding_enabled(padding_enabled)
{
}

void AesAlgo::PadInputBlock(std::vector<uint8_t>& in)
{
	size_t remainder = in.size() % blockBytesLen;
    if (remainder != 0) {
        size_t padding_needed = blockBytesLen - remainder;
        in.insert(in.end(), padding_needed, 0xFF);
    }
}

void AesAlgo::CheckLength(uint16_t len)
{
	if (len % blockBytesLen != 0)
	{
		// throw std::length_error("Plaintext length must be divisible by " +
		// 						std::to_string(blockBytesLen));
		std::cout << "Plaintext length must be divisible by " << blockBytesLen << std::endl;
	}
}

uint8_t AesAlgo::multiply_gf256(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t temp_b = b;

    for (int i = 0; i < 8  && b ; i++){
        if (temp_b & 0x01) { // If the LSB of temp_b is 1, add 'a' to the result
            result ^= a;
        }
        // Multiply 'a' by x (0x02)
        a = xtime(a);
        // Right shift temp_b to process the next bit
        temp_b >>= 1;
    }
    return result;
}

/**
 * @brief Encrypts a single 16-byte block using the AES algorithm.
 *
 * @param in The 16-byte input block to encrypt.
 * @param out The 16-byte output block to store the encrypted data.
 * @param roundKeys The expanded key schedule.
 */
void AesAlgo::EncryptBlock(std::vector<uint8_t> &in,
						   std::vector<uint8_t> &out,
						   std::vector<uint8_t> &roundKeys)
{
	// The state is a 4x4 matrix of bytes, which is the core data structure in AES.
	std::array<std::array<uint8_t, Nb>, 4> state;
	uint16_t round;
	std::vector<uint8_t> rk(16);

	// Copy the input block into the state matrix (column by column).
	for (uint16_t i = 0; i < 4; i++) {
		for (uint16_t j = 0; j < Nb; j++) {
			state[i][j] = in[i + 4 * j];
		}
	}

	// Initial round: Add the first round key to the state.
	rk.clear(); // using clear to keep the capacity unchanged
	rk.assign(roundKeys.begin(), (roundKeys.begin() + 4 * Nb));
	AddRoundKey(state, rk);

	// Main rounds: Perform Nr-1 rounds of transformations.
	for (round = 1; round <= Nr - 1; round++)
	{
		// SubBytes: Substitute bytes using the S-box.
		SubBytes(state);
		// ShiftRows: Cyclically shift the rows of the state.
		ShiftRows(state);
		// MixColumns: Mix the columns of the state.
		MixColumns(state);
		// AddRoundKey: XOR the state with the round key for this round.
		rk.assign((roundKeys.begin() + round * 4 * Nb), (roundKeys.begin() + (round + 1) * 4 * Nb));
		AddRoundKey(state, rk);
	}

	// Final round: Similar to the main rounds but without the MixColumns step.
	SubBytes(state);
	ShiftRows(state);
	
	rk.clear(); // using clear to keep the capacity unchanged
	rk.assign(roundKeys.begin() + Nr * 4 * Nb, roundKeys.end());
	AddRoundKey(state, rk);

	// Copy the final state matrix to the output block (column by column).		
	out.resize(16); // ensure output has correct size
	out.reserve(16);
	for (size_t i = 0; i < 4; i++) {
    	for (size_t j = 0; j < Nb; j++) {
        	out[i + 4*j] = state[i][j]; // column-major mapping
    	}
	}
}

/**
 * @brief Decrypts a single 16-byte block using the AES algorithm.
 *
 * @param in The 16-byte input block to decrypt (ciphertext).
 * @param out The 16-byte output block to store the decrypted data (plaintext).
 * @param roundKeys The expanded key schedule.
 */
void AesAlgo::DecryptBlock(std::vector<uint8_t> &in,
						   std::vector<uint8_t> &out,
						   std::vector<uint8_t> &roundKeys)
{
	// The state is a 4x4 matrix of bytes, which is the core data structure in AES.
	std::array<std::array<uint8_t, Nb>, 4> state;
	uint16_t i, j, round;
	std::vector<uint8_t> rk(16);

	// Copy the input block (ciphertext) into the state matrix (column by column).
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			state[i][j] = in[i + 4 * j];
		}
	}
	// Initial round: Add the last round key to the state.
	rk.clear(); // using clear to keep the capacity unchanged
	rk.assign(roundKeys.begin() + Nr * 4 * Nb, roundKeys.end());
	AddRoundKey(state, rk);

	// Main rounds: Perform Nr-1 rounds of inverse transformations.
	for (round = Nr - 1; round >= 1; round--)
	{
		// InvSubBytes: Substitute bytes using the inverse S-box.
		InvSubBytes(state);

		// InvShiftRows: Cyclically shift the rows of the state in the opposite direction.
		InvShiftRows(state);

		// AddRoundKey: XOR the state with the round key for this round.
		rk.assign((roundKeys.begin() + round * 4 * Nb), (roundKeys.begin() + (round + 1) * 4 * Nb));
		AddRoundKey(state, rk);
		// InvMixColumns: Mix the columns of the state using the inverse matrix.
		InvMixColumns(state);
	}

	// Final round: Similar to the main rounds but without the InvMixColumns step.
	InvSubBytes(state);
	InvShiftRows(state);

	rk.clear(); // using clear to keep the capacity unchanged
	rk.assign(roundKeys.begin(), (roundKeys.begin() + 4 * Nb));
	AddRoundKey(state, rk);

	// Copy the final state matrix to the output block (column by column).		
	out.resize(16); // ensure output has correct size
	out.reserve(16);
	// Copy the final state matrix to the output block (plaintext).
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			out[i + 4 * j] = state[i][j];
		}
	}
}

/**
 * @brief Applies the SubBytes transformation to the state matrix.
 * Each byte of the state is replaced with the corresponding byte from the S-box.
 * @param state The 4x4 state matrix.
 */
void AesAlgo::SubBytes(std::array<std::array<uint8_t, Nb>, 4> &state)
{
	uint16_t i, j;
	uint8_t t;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			t = state[i][j];
			state[i][j] = sbox[t / 16][t % 16];
		}
	}
}

/**
 * @brief Cyclically shifts a single row of the state matrix.
 *
 * @param state The 4x4 state matrix.
 * @param i The index of the row to shift.
 * @param n The number of positions to shift the row to the left.
 */
void AesAlgo::ShiftRow(std::array<std::array<uint8_t, Nb>, 4> &state,
					   uint16_t i,
					   uint16_t n)
{
	std::array<uint8_t, Nb> tmp;
    for (uint16_t j = 0; j < Nb; j++)
    {
        tmp[j] = state[i][(j + n) % Nb];
    }
    state[i] = tmp;
}

/**
 * @brief Applies the ShiftRows transformation to the state matrix.
 * Rows 1, 2, and 3 are shifted by 1, 2, and 3 positions respectively.
 * @param state The 4x4 state matrix.
 */
void AesAlgo::ShiftRows(std::array<std::array<uint8_t, Nb>, 4> &state)
{
	ShiftRow(state, 1, 1);
	ShiftRow(state, 2, 2);
	ShiftRow(state, 3, 3);
}

/**
 * @brief Performs multiplication by x (i.e., by 2) in the Galois Field GF(2^8).
 * This is a core operation for the MixColumns step.
 * @param b The byte to multiply.
 * @return The result of the multiplication.
 */
uint8_t AesAlgo::xtime(uint8_t b) // multiply on x
{
	return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

/**
 * @brief Applies the MixColumns transformation to the state matrix.
 * Each column is transformed by multiplying it with a fixed polynomial.
 * @param state The 4x4 state matrix.
 */
void AesAlgo::MixColumns(std::array<std::array<uint8_t, Nb>, 4> &state)
{
	std::array<std::array<uint8_t, Nb>, 4> temp_state{};
	// Using precomputed Galois Field multiplication tables for efficiency
	if (!_gf_enabled)
	{
		for (size_t i = 0; i < 4; ++i)
		{
			for (size_t k = 0; k < 4; ++k)
			{
				for (size_t j = 0; j < 4; ++j)
				{
					if (CMDS[i][k] == 1)
						temp_state[i][j] ^= state[k][j];
					else
						temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
				}
			}
		}

		for (size_t i = 0; i < 4; ++i)
		{
			state[i] = temp_state[i];
		}
	}
	else
	{
		// Same accumulation style as the table-based path, but using multiply_gf256
		for (std::size_t i = 0; i < 4; ++i)
		{
			for (std::size_t k = 0; k < 4; ++k)
			{
				const uint8_t multiplier = static_cast<uint8_t>(CMDS[i][k]);
				for (std::size_t j = 0; j < Nb; ++j)
				{
					if (multiplier == 1)
					{
						temp_state[i][j] ^= state[k][j];
					}
					else
					{
						temp_state[i][j] ^= multiply_gf256(multiplier, state[k][j]);
					}
				}
			}
		}

		for (std::size_t i = 0; i < 4; ++i)
		{
			state[i] = temp_state[i];
		}
	}
}

/**
 * @brief Applies the AddRoundKey transformation to the state matrix.
 * The state is XORed with the round key.
 * @param state The 4x4 state matrix.
 * @param key The round key to add.
 */
void AesAlgo::AddRoundKey(std::array<std::array<uint8_t, Nb>, 4> &state,
						  std::vector<uint8_t> &key)
{
	uint16_t i, j;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			state[i][j] = state[i][j] ^ key[i + 4 * j];
		}
	}
}

/**
 * @brief Applies the S-box to a 4-byte word.
 * This is part of the KeyExpansion schedule.
 * @param a The 4-byte word to transform.
 */
void AesAlgo::SubWord(std::vector<uint8_t> &a)
{
	int i;
	for (i = 0; i < 4; i++)
	{
		a[i] = sbox[a[i] / 16][a[i] % 16];
	}
}

/**
 * @brief Performs a cyclic permutation on a 4-byte word.
 * This is part of the KeyExpansion schedule.
 * @param a The 4-byte word to rotate.
 */
void AesAlgo::RotWord(std::vector<uint8_t> &a)
{
	uint8_t c = a[0];
	a[0] = a[1];
	a[1] = a[2];
	a[2] = a[3];
	a[3] = c;
}

/**
 * @brief XORs two 4-byte words and stores the result in a third word.
 *
 * @param a The first 4-byte word.
 * @param b The second 4-byte word.
 * @param c The 4-byte word to store the result.
 */
void AesAlgo::XorWords(std::vector<uint8_t> &a,
					   std::vector<uint8_t> &b,
					   std::vector<uint8_t> &c)
{
	int i;
	for (i = 0; i < 4; i++)
	{
		c[i] = a[i] ^ b[i];
	}
}

/**
 * @brief Generates the round constant (Rcon) for a given round number.
 *
 * @param a The 4-byte word to store the Rcon value.
 * @param n The round number.
 */
void AesAlgo::Rcon(std::vector<uint8_t> &a, uint16_t n)
{
	uint16_t i;
	uint8_t c = 1;
	for (i = 0; i < n - 1; i++)
	{
		c = xtime(c);
	}

	a[0] = c;
	a[1] = a[2] = a[3] = 0;
}

/**
 * @brief Expands the initial key into a key schedule.
 *
 * @param key The initial cipher key.
 * @param w The expanded key schedule.
 */
void AesAlgo::KeyExpansion(std::vector<uint8_t> &key,
						   std::vector<uint8_t> &w)
{
	std::vector<uint8_t> temp(4);
	std::vector<uint8_t> rcon(4);
	uint16_t i = 0;
	w.resize(4 * Nb * (Nr + 1));

	// The first Nk words of the expanded key are filled with the original key.
	while (i < 4 * Nk)
	{
		w[i] = key[i];
		i++;
	}

	// Generate the remaining words of the expanded key.
	i = 4 * Nk;
	while (i < 4 * Nb * (Nr + 1))
	{
		// Take the previous 4-byte word.
		temp[0] = w[i - 4 + 0];
		temp[1] = w[i - 4 + 1];
		temp[2] = w[i - 4 + 2];
		temp[3] = w[i - 4 + 3];

		// Apply the key schedule core transformation every Nk words.
		if (i / 4 % Nk == 0)
		{
			// RotWord: Cyclically shift the bytes of the word.
			RotWord(temp);

			// SubWord: Apply the S-box to each byte of the word.
			SubWord(temp);
		
			// Rcon: XOR with a round constant.
			Rcon(rcon, i / (Nk * 4));
			
			XorWords(temp, rcon, temp);
		}

		// The new word is the XOR of the word from Nk positions back and the transformed temporary word.
		w[i + 0] = w[i - 4 * Nk] ^ temp[0];
		w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
		w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
		w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
		// Move to the next 4-byte word.
		i += 4;
	}
}

/**
 * @brief Applies the inverse SubBytes transformation to the state matrix.
 * Each byte of the state is replaced with the corresponding byte from the inverse S-box.
 * @param state The 4x4 state matrix.
 */
void AesAlgo::InvSubBytes(std::array<std::array<uint8_t, Nb>, 4> &state)
{
	uint16_t i, j;
	uint8_t t;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			t = state[i][j];
			state[i][j] = inv_sbox[t / 16][t % 16];
		}
	}
}

/**
 * @brief Applies the inverse MixColumns transformation to the state matrix.
 * Each column is transformed by multiplying it with the inverse of the fixed polynomial.
 * @param state The 4x4 state matrix.
 */
void AesAlgo::InvMixColumns(std::array<std::array<uint8_t, Nb>, 4> &state)
{
	std::array<std::array<uint8_t, Nb>, 4> temp_state{};

	for (size_t i = 0; i < 4; ++i)
	{
		for (size_t k = 0; k < 4; ++k)
		{
			for (size_t j = 0; j < 4; ++j)
			{
				temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
			}
		}
	}

	for (size_t i = 0; i < 4; ++i)
	{
		state[i] = temp_state[i];
	}
}

/**
 * @brief Applies the inverse ShiftRows transformation to the state matrix.
 * Rows 1, 2, and 3 are shifted in the opposite direction of ShiftRows.
 * @param state The 4x4 state matrix.
 */
void AesAlgo::InvShiftRows(std::array<std::array<uint8_t, Nb>, 4> &state)
{
	ShiftRow(state, 1, Nb - 1);
	ShiftRow(state, 2, Nb - 2);
	ShiftRow(state, 3, Nb - 3);
}

/**
 * @brief XORs two blocks of bytes and stores the result in a third block.
 *
 * @param a The first block.
 * @param b The second block.
 * @param c The block to store the result.
 * @param len The length of the blocks.
 */
void AesAlgo::XorBlocks(std::vector<uint8_t> &a,
						std::vector<uint8_t> &b,
						std::vector<uint8_t> &c,
						uint16_t len)
{
	for (uint16_t i = 0; i < len; i++)
	{
		c[i] = a[i] ^ b[i];
	}
}

void AesAlgo::printHexVector(std::vector<uint8_t> a)
{
	for (uint16_t i = 0; i < a.size(); i++)
	{
		printf("%02x ", a[i]);
	}
}

/**
 * @brief Encrypts data using AES in ECB (Electronic Codebook) mode.
 */
std::vector<uint8_t> AesAlgo::EncryptECB(std::vector<uint8_t> in,
										 std::vector<uint8_t> key)
{
	uint16_t inLen = in.size();
if (_padding_enabled != true)
{
	CheckLength(inLen);
}
else
{
	PadInputBlock(in);
}
	std::vector<uint8_t> out;
	std::vector<uint8_t> roundKeys;
	KeyExpansion(key, roundKeys);
	
	for (uint16_t i = 0; i < inLen; i += blockBytesLen)
	{
		std::vector<uint8_t> in_block(in.begin() + i, in.begin() + i + blockBytesLen);
		std::vector<uint8_t> out_block(blockBytesLen);
		EncryptBlock(in_block, out_block, roundKeys);
		out.insert(out.end(), out_block.begin(), out_block.end());
	}
	return out;
}

/**
 * @brief Decrypts data using AES in ECB (Electronic Codebook) mode.
 */
std::vector<uint8_t> AesAlgo::DecryptECB(std::vector<uint8_t> in,
										 std::vector<uint8_t> key)
{
	uint16_t inLen = in.size();
	CheckLength(inLen);
	std::vector<uint8_t> out;
	std::vector<uint8_t> roundKeys;
	KeyExpansion(key, roundKeys);

	for (uint16_t i = 0; i < inLen; i += blockBytesLen)
	{
		std::vector<uint8_t> in_block(in.begin() + i, in.begin() + i + blockBytesLen);
		std::vector<uint8_t> out_block(blockBytesLen);
		DecryptBlock(in_block, out_block, roundKeys);
		out.insert(out.end(), out_block.begin(), out_block.end());
	}
	
	return out;
}

/**
 * @brief Encrypts data using AES in CBC (Cipher Block Chaining) mode.
 */
std::vector<uint8_t> AesAlgo::EncryptCBC(std::vector<uint8_t> in,
										 std::vector<uint8_t> key,
										 std::vector<uint8_t> iv)
{
	uint16_t inLen = in.size();
if (_padding_enabled != true)
{
	CheckLength(inLen);
}
else
{
	PadInputBlock(in);
}
	std::vector<uint8_t> out;
	std::vector<uint8_t> block = iv;
	block.resize(blockBytesLen);
	std::vector<uint8_t> roundKeys(4 * Nb * (Nr + 1));
	KeyExpansion(key, roundKeys);

	for (uint16_t i = 0; i < inLen; i += blockBytesLen)
	{
		std::vector<uint8_t> in_block(in.begin() + i, in.begin() + i + blockBytesLen);
		XorBlocks(block, in_block, block, blockBytesLen);
		EncryptBlock(block, block, roundKeys);
		out.insert(out.end(), block.begin(), block.end());
	}
	return out;
}

/**
 * @brief Decrypts data using AES in CBC (Cipher Block Chaining) mode.
 */
std::vector<uint8_t> AesAlgo::DecryptCBC(std::vector<uint8_t> in,
										 std::vector<uint8_t> key,
										 std::vector<uint8_t> iv)
{
	uint16_t inLen = in.size();
	CheckLength(inLen);
	std::vector<uint8_t> out;
	std::vector<uint8_t> prev_block = iv;
	prev_block.resize(blockBytesLen);
	std::vector<uint8_t> roundKeys(4 * Nb * (Nr + 1));
	KeyExpansion(key, roundKeys);

	for (uint16_t i = 0; i < inLen; i += blockBytesLen)
	{
		std::vector<uint8_t> in_block(in.begin() + i, in.begin() + i + blockBytesLen);
		std::vector<uint8_t> out_block(blockBytesLen);
		DecryptBlock(in_block, out_block, roundKeys);
		XorBlocks(prev_block, out_block, out_block, blockBytesLen);
		out.insert(out.end(), out_block.begin(), out_block.end());
		prev_block = in_block;
	}
	return out;
}

/**
 * @brief Encrypts data using AES in CFB (Cipher Feedback) mode.
 */
std::vector<uint8_t> AesAlgo::EncryptCFB(std::vector<uint8_t> in,
										 std::vector<uint8_t> key,
										 std::vector<uint8_t> iv)
{
	uint16_t inLen = in.size();
if (_padding_enabled != true)
{
	CheckLength(inLen);
}
else
{
	PadInputBlock(in);
}
	std::vector<uint8_t> out;
	std::vector<uint8_t> block = iv;
	block.resize(blockBytesLen);
	std::vector<uint8_t> encryptedBlock(blockBytesLen);
	std::vector<uint8_t> roundKeys(4 * Nb * (Nr + 1));
	KeyExpansion(key, roundKeys);

	for (uint16_t i = 0; i < inLen; i += blockBytesLen)
	{
		EncryptBlock(block, encryptedBlock, roundKeys);
		std::vector<uint8_t> in_block(in.begin() + i, in.begin() + i + blockBytesLen);
		XorBlocks(in_block, encryptedBlock, block, blockBytesLen);
		out.insert(out.end(), block.begin(), block.end());
	}
	return out;
}

/**
 * @brief Decrypts data using AES in CFB (Cipher Feedback) mode.
 */
std::vector<uint8_t> AesAlgo::DecryptCFB(std::vector<uint8_t> in,
											   std::vector<uint8_t> key,
											   std::vector<uint8_t> iv)
{
	uint16_t inLen = in.size();
	CheckLength(inLen);
	std::vector<uint8_t> out;
	std::vector<uint8_t> block = iv;
	block.resize(blockBytesLen);
	std::vector<uint8_t> encryptedBlock(blockBytesLen);
	std::vector<uint8_t> roundKeys(4 * Nb * (Nr + 1));
	KeyExpansion(key, roundKeys);

	for (uint16_t i = 0; i < inLen; i += blockBytesLen)
	{
		EncryptBlock(block, encryptedBlock, roundKeys);
		std::vector<uint8_t> in_block(in.begin() + i, in.begin() + i + blockBytesLen);
		XorBlocks(in_block, encryptedBlock, block, blockBytesLen);
		out.insert(out.end(), block.begin(), block.end());
		block = in_block;
	}
	return out;
}

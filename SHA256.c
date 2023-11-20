#include "main.h"
#include "SHA_TABLE.h"


//sha256 방식의 패딩 
//input:64바이트가 안되는 메세지의 시작 주소 
//pt_len:64바이트가 안되는 input의 길이(단위:바이트)
//MSG_LEN:원본 메세지 길이
void SHA256_padding(uint8_t* input, uint32_t pt_len, uint32_t MSG_LEN) {
	//메세지 길이를 bit기준으로 표현했을때 -> 8바이트로 표현
	uint8_t bit_len[8];
	unsigned long long int bit_MSG_LEN = (unsigned long long int)8 * MSG_LEN;
	bit_len[0] = (bit_MSG_LEN >> 56) & 0xff;
	bit_len[1] = (bit_MSG_LEN >> 48) & 0xff;
	bit_len[2] = (bit_MSG_LEN >> 40) & 0xff;
	bit_len[3] = (bit_MSG_LEN >> 32) & 0xff;
	bit_len[4] = (bit_MSG_LEN >> 24) & 0xff;
	bit_len[5] = (bit_MSG_LEN >> 16) & 0xff;
	bit_len[6] = (bit_MSG_LEN >> 8) & 0xff;
	bit_len[7] = (bit_MSG_LEN) & 0xff;

	//msg sha256방식의 패딩 시작 부분
	input[0] = 0x80;
	memset(input + 1, 0x00, (pt_len - 7));
	memcpy(input + (pt_len - 8), bit_len, 8);
}

//SHA256 연산함수
void SHA256(uint8_t* MSG, uint64_t MSG_len, uint8_t* output) {
	//initial hash value
	//이 값을 계속 update 시킨다음 결과값을 output에 memcpy 할것
	uint32_t H[8] = { 0x6a09e667 ,0xbb67ae85 ,0x3c6ef372 ,0xa54ff53a , 0x510e527f ,0x9b05688c ,0x1f83d9ab, 0x5be0cd19 };

	uint64_t new_ptlen = 0;
	uint8_t* new_MSG = NULL;
	//msg에 패딩할지 말지를 결정해서 -> 패딩유무 실행!
	if (MSG_len % 64 != 0) {
		new_ptlen = MSG_len % 64 < 56 ? MSG_len + (64 - (MSG_len % 64)) : MSG_len + (64 - (MSG_len % 64)) + 64;
		new_MSG = (uint8_t*)calloc(new_ptlen, sizeof(uint8_t));
		assert(new_MSG != NULL);
		//padding 되기전까지 기존 msg 복사
		memcpy(new_MSG, MSG, MSG_len * sizeof(uint8_t));
		//패딩실행
		SHA256_padding((new_MSG + MSG_len), new_ptlen - MSG_len, MSG_len);
	}
	else {//패딩 안해도 됨
		new_ptlen = MSG_len;
		new_MSG = (uint8_t*)calloc(new_ptlen, sizeof(uint8_t));
		assert(new_MSG != NULL);
		memcpy(new_MSG, MSG, new_ptlen * sizeof(uint8_t));
	}

	//sha256 결과값 만들기
	int loop = new_ptlen >> 6; // /64랑 동일한 의미 -> 속도는 더 빠름!
	int cnt_i, cnt_j;
	uint32_t W[64] = { 0x00, };
	for (cnt_i = 0; cnt_i < loop; cnt_i++) {
		//message schedule
		cut_st(new_MSG + (64 * cnt_i), W);
		W[16] = df1(W[14]) + W[9] + df0(W[1]) + W[0];
		W[17] = df1(W[15]) + W[10] + df0(W[2]) + W[1];
		W[18] = df1(W[16]) + W[11] + df0(W[3]) + W[2];
		W[19] = df1(W[17]) + W[12] + df0(W[4]) + W[3];
		W[20] = df1(W[18]) + W[13] + df0(W[5]) + W[4];
		W[21] = df1(W[19]) + W[14] + df0(W[6]) + W[5];
		W[22] = df1(W[20]) + W[15] + df0(W[7]) + W[6];
		W[23] = df1(W[21]) + W[16] + df0(W[8]) + W[7];
		W[24] = df1(W[22]) + W[17] + df0(W[9]) + W[8];
		W[25] = df1(W[23]) + W[18] + df0(W[10]) + W[9];
		W[26] = df1(W[24]) + W[19] + df0(W[11]) + W[10];
		W[27] = df1(W[25]) + W[20] + df0(W[12]) + W[11];
		W[28] = df1(W[26]) + W[21] + df0(W[13]) + W[12];
		W[29] = df1(W[27]) + W[22] + df0(W[14]) + W[13];
		W[30] = df1(W[28]) + W[23] + df0(W[15]) + W[14];
		W[31] = df1(W[29]) + W[24] + df0(W[16]) + W[15];
		W[32] = df1(W[30]) + W[25] + df0(W[17]) + W[16];
		W[33] = df1(W[31]) + W[26] + df0(W[18]) + W[17];
		W[34] = df1(W[32]) + W[27] + df0(W[19]) + W[18];
		W[35] = df1(W[33]) + W[28] + df0(W[20]) + W[19];
		W[36] = df1(W[34]) + W[29] + df0(W[21]) + W[20];
		W[37] = df1(W[35]) + W[30] + df0(W[22]) + W[21];
		W[38] = df1(W[36]) + W[31] + df0(W[23]) + W[22];
		W[39] = df1(W[37]) + W[32] + df0(W[24]) + W[23];
		W[40] = df1(W[38]) + W[33] + df0(W[25]) + W[24];
		W[41] = df1(W[39]) + W[34] + df0(W[26]) + W[25];
		W[42] = df1(W[40]) + W[35] + df0(W[27]) + W[26];
		W[43] = df1(W[41]) + W[36] + df0(W[28]) + W[27];
		W[44] = df1(W[42]) + W[37] + df0(W[29]) + W[28];
		W[45] = df1(W[43]) + W[38] + df0(W[30]) + W[29];
		W[46] = df1(W[44]) + W[39] + df0(W[31]) + W[30];
		W[47] = df1(W[45]) + W[40] + df0(W[32]) + W[31];
		W[48] = df1(W[46]) + W[41] + df0(W[33]) + W[32];
		W[49] = df1(W[47]) + W[42] + df0(W[34]) + W[33];
		W[50] = df1(W[48]) + W[43] + df0(W[35]) + W[34];
		W[51] = df1(W[49]) + W[44] + df0(W[36]) + W[35];
		W[52] = df1(W[50]) + W[45] + df0(W[37]) + W[36];
		W[53] = df1(W[51]) + W[46] + df0(W[38]) + W[37];
		W[54] = df1(W[52]) + W[47] + df0(W[39]) + W[38];
		W[55] = df1(W[53]) + W[48] + df0(W[40]) + W[39];
		W[56] = df1(W[54]) + W[49] + df0(W[41]) + W[40];
		W[57] = df1(W[55]) + W[50] + df0(W[42]) + W[41];
		W[58] = df1(W[56]) + W[51] + df0(W[43]) + W[42];
		W[59] = df1(W[57]) + W[52] + df0(W[44]) + W[43];
		W[60] = df1(W[58]) + W[53] + df0(W[45]) + W[44];
		W[61] = df1(W[59]) + W[54] + df0(W[46]) + W[45];
		W[62] = df1(W[60]) + W[55] + df0(W[47]) + W[46];
		W[63] = df1(W[61]) + W[56] + df0(W[48]) + W[47];

		//initialize the eight working variables a~h
		uint32_t a = H[0];
		uint32_t b = H[1];
		uint32_t c = H[2];
		uint32_t d = H[3];
		uint32_t e = H[4];
		uint32_t f = H[5];
		uint32_t g = H[6];
		uint32_t h = H[7];

		//a~h value update!
		for (cnt_j = 0; cnt_j < 64; cnt_j++) {
			uint32_t T1 = h + sigma1(e) + CH(e, f, g) + K[cnt_j] + W[cnt_j];
			uint32_t T2 = sigma0(a) + Maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

		//Compute the H_value
		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
	}

	//SHA_256 결과값 처리
	WordToByte(H, output);

	//동적메모리 해제
	free(new_MSG);
	new_MSG = NULL;
}


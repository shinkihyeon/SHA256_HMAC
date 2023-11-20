#include "main.h"

// 4byte * 8 -> 1byte * 32
void WordToByte(uint32_t* input, uint8_t* output) {
	output[0] = (input[0] >> 24);
	output[1] = (input[0] >> 16) & 0xff;
	output[2] = (input[0] >> 8) & 0xff;
	output[3] = (input[0]) & 0xff;
	output[4] = (input[1] >> 24);
	output[5] = (input[1] >> 16) & 0xff;
	output[6] = (input[1] >> 8) & 0xff;
	output[7] = (input[1]) & 0xff;
	output[8] = (input[2] >> 24);
	output[9] = (input[2] >> 16) & 0xff;
	output[10] = (input[2] >> 8) & 0xff;
	output[11] = (input[2]) & 0xff;
	output[12] = (input[3] >> 24);
	output[13] = (input[3] >> 16) & 0xff;
	output[14] = (input[3] >> 8) & 0xff;
	output[15] = (input[3]) & 0xff;
	output[16] = (input[4] >> 24);
	output[17] = (input[4] >> 16) & 0xff;
	output[18] = (input[4] >> 8) & 0xff;
	output[19] = (input[4]) & 0xff;
	output[20] = (input[5] >> 24);
	output[21] = (input[5] >> 16) & 0xff;
	output[22] = (input[5] >> 8) & 0xff;
	output[23] = (input[5]) & 0xff;
	output[24] = (input[6] >> 24);
	output[25] = (input[6] >> 16) & 0xff;
	output[26] = (input[6] >> 8) & 0xff;
	output[27] = (input[6]) & 0xff;
	output[28] = (input[7] >> 24);
	output[29] = (input[7] >> 16) & 0xff;
	output[30] = (input[7] >> 8) & 0xff;
	output[31] = (input[7]) & 0xff;
}

//전체 msg에서 해당 번째 시작주소를 주면 거기서부터 64바이트 만큼을 
//4바이트 * 16 big-endian형식으로 output에 넣어주는 함수
void cut_st(uint8_t* input, uint32_t* output) {
	output[0] = input[0] << 24 | input[1] << 16 | input[2] << 8 | input[3];
	output[1] = input[4] << 24 | input[5] << 16 | input[6] << 8 | input[7];
	output[2] = input[8] << 24 | input[9] << 16 | input[10] << 8 | input[11];
	output[3] = input[12] << 24 | input[13] << 16 | input[14] << 8 | input[15];
	output[4] = input[16] << 24 | input[17] << 16 | input[18] << 8 | input[19];
	output[5] = input[20] << 24 | input[21] << 16 | input[22] << 8 | input[23];
	output[6] = input[24] << 24 | input[25] << 16 | input[26] << 8 | input[27];
	output[7] = input[28] << 24 | input[29] << 16 | input[30] << 8 | input[31];
	output[8] = input[32] << 24 | input[33] << 16 | input[34] << 8 | input[35];
	output[9] = input[36] << 24 | input[37] << 16 | input[38] << 8 | input[39];
	output[10] = input[40] << 24 | input[41] << 16 | input[42] << 8 | input[43];
	output[11] = input[44] << 24 | input[45] << 16 | input[46] << 8 | input[47];
	output[12] = input[48] << 24 | input[49] << 16 | input[50] << 8 | input[51];
	output[13] = input[52] << 24 | input[53] << 16 | input[54] << 8 | input[55];
	output[14] = input[56] << 24 | input[57] << 16 | input[58] << 8 | input[59];
	output[15] = input[60] << 24 | input[61] << 16 | input[62] << 8 | input[63];
}

#ifndef FUNC_H
#define FUNC_H

#include <stdint.h>

#define BYTE_SIZE_1 8
#define BYTE_SIZE_2 16
#define BYTE_SIZE_3 24


typedef uint32_t (*FUNCPTR)(uint32_t, uint32_t, uint32_t);

class Func
{
public:
	static void initVector(FUNCPTR *vector)
	{
		vector[0] = execute0;
		vector[1] = execute1;
		vector[2] = execute2;
		vector[3] = execute3;
	}
	
	static uint32_t execute0(uint32_t t, uint32_t m, uint32_t it)
	{
		uint32_t newt;
		uint16_t mask = m & 0x0000FFFF;
		uint8_t lmask = (mask & 0xFF00) >> BYTE_SIZE_1;
		//uint8_t rmask = (mask & 0xFF);
		uint8_t s1[] = {0,3,4};
		uint8_t s2[] = {1,2,4};
		
		newt = t ^ (lmask << BYTE_SIZE_3 | lmask << BYTE_SIZE_2 | lmask << BYTE_SIZE_1 | lmask);
		
		newt = f1(newt, s1);
		newt = f1(newt, s2);
		
		return newt;
	}

	static uint32_t execute1(uint32_t t, uint32_t m, uint32_t it)
	{
		uint32_t newt;
		uint16_t mask = m & 0x0000FFFF;
		uint8_t lmask = (mask & 0xFF00) >> BYTE_SIZE_1;
		uint8_t rmask = (mask & 0xFF);
		uint8_t s1[] = {0,2,4};
		
		newt = t ^ (rmask << BYTE_SIZE_3 | lmask << BYTE_SIZE_2 | rmask << BYTE_SIZE_1 | lmask);
		newt = newt + it;
		
		newt = f1(newt, s1);
		
		return newt;
	}

	static uint32_t execute2(uint32_t t, uint32_t m, uint32_t it)
	{
		uint32_t newt;
		uint8_t s1[] = {0,2,4};
		
		newt = t ^ it;
		newt = f1(newt, s1);
		
		return newt;
	}

	static uint32_t execute3(uint32_t t, uint32_t m, uint32_t it)
	{
		uint32_t newt;
		uint8_t s1[] = {0,1,4};
		uint16_t mask = m & 0x0000FFFF;
		uint8_t lmask = (mask & 0xFF00) >> BYTE_SIZE_1;
		uint8_t rmask = (mask & 0xFF);

		newt = t ^ (lmask << BYTE_SIZE_3 | rmask << BYTE_SIZE_2 | rmask << BYTE_SIZE_1 | rmask);
		
		newt = newt * it;
		newt = f1(newt, s1);
		
		return newt;
	}

private:
	static uint32_t f1(uint32_t t, uint8_t *s)
	{
		uint8_t aux1, aux2;
		uint8_t val;
		uint8_t i;
		uint32_t newt;
		
		if (s[0] != 4)
		{
			aux1 = ((t >> (s[0] * BYTE_SIZE_1)) & 0xFF);
			aux2 = ((t >> (s[1] * BYTE_SIZE_1)) & 0xFF);
			
			val = 0;
			for (i=0;i<4;i++)
			{
				if (i != s[0] && i != s[1])
				{
					val = val | (0xFF << (i * BYTE_SIZE_1));
				}
			}
			
			newt = ((t & val) | (aux2 << (s[0] * BYTE_SIZE_1)) | (aux1 << (s[1] * BYTE_SIZE_1)));
		}
		
		return newt;
	}
};

#endif //FUNC_H

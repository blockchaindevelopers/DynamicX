/**
 * Copyright 2017 Everybody and Nobody (Empinel/Plaxton)
 * 
 * This file is a portion of the DynamicX Protocol
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation files 
 * (the "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject 
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE 
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define PrimaryDelimiter "~"
#define SubDelimiter "||"
#define SignatureDelimiter " "
/*
class Base64Functions {
};
*/
class HexFunctions {
private:
	// C++98 guarantees that '0', '1', ... '9' are consecutive.
	// It only guarantees that 'a' ... 'f' and 'A' ... 'F' are
	// in increasing order, but the only two alternative encodings
	// of the basic source character set that are still used by
	// anyone today (ASCII and EBCDIC) make them consecutive.
	unsigned char hexval(unsigned char c)
	{
		if ('0' <= c && c <= '9')
			return c - '0';
		else if ('a' <= c && c <= 'f')
			return c - 'a' + 10;
		else if ('A' <= c && c <= 'F')
			return c - 'A' + 10;
		else abort();
	}

	// TODO: Switch to CryptoPP
	std::string StringToHex(std::string input) {
		static const char* const lut = "0123456789ABCDEF";
		size_t len = input.length();
		std::string output;
		output.reserve(2 * len);
		for (size_t i = 0; i < len; ++i)
		{
			const unsigned char c = input[i];
			output.push_back(lut[c >> 4]);
			output.push_back(lut[c & 15]);
		}
		
		return output;
	}
	
	// TODO: Switch to CryptoPP
	std::string HexToString(std::string in) {
		std::string out;
		out.clear();
		out.reserve(in.length() / 2);
		for (std::string::const_iterator p = in.begin(); p != in.end(); p++)
		{
		   unsigned char c = hexval(*p);
		   p++;
		   if (p == in.end()) break; // incomplete last digit - should report error
		   c = (c << 4) + hexval(*p); // + takes precedence over <<
		   out.push_back(c);
		}
		return out;
	}
	
public:
	void ConvertToHex(std::string &input) { std::string output = StringToHex(input); input = output; }
	void ConvertToString(std::string &input) { std::string output = HexToString(input); input = output; }
};

/* String Manipulation Functions */
void ScrubString(std::string &input);
void SeperateString(std::string input, std::vector<std::string> output);
std::string StitchString(std::string stringOne, std::string stringTwo);
std::string StitchString(std::string stringOne, std::string stringTwo, std::string stringThree);

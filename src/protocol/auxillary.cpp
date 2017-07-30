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

void ScrubString(std::string &input) {
	input.erase(std::remove(input.begin(), input.end(), TransactionDelimiter), input.end());
	input.erase(std::remove(input.begin(), input.end(), SubDelimiter), input.end());
}

void SeperateString(std::string input, std::vector<std::string> output, bool subDelimiter = false) {
	if(subDelimiter)
		boost::split(output, input, boost::is_any_of(TransactionDelimiter));
	else
		boost::split(output, input, boost::is_any_of(SubDelimiter));
};

std::string StitchString(std::string stringOne, std::string stringTwo, bool subDelimiter = false) {
	ScrubString(stringOne); ScrubString(stringTwo);
	
	if(subDelimiter)
		return stringOne + SubDelimiter + stringTwo;
	else 
		return stringOne + TransactionDelimiter + stringTwo;
}

std::string StitchString(std::string stringOne, std::string stringTwo, std::string stringThree, bool subDelimiter = false) {
	ScrubString(stringOne); ScrubString(stringTwo);
	
	if(subDelimiter)
		return stringOne + SubDelimiter + stringTwo + SubDelimiter + stringThree;
	else 
		return stringOne + TransactionDelimiter + stringTwo + TransactionDelimiter + stringThree;
}

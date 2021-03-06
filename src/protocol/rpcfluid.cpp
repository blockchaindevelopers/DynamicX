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

#include "protocol/fluid.h"

#include "core_io.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "init.h"
#include "keepass.h"
#include "net.h"
#include "netbase.h"
#include "rpcserver.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "main.h"
#include "chain.h"

#include <univalue.h>

extern bool EnsureWalletIsAvailable(bool avoidException);
extern void SendCustomTransaction(CScript generatedScript, CWalletTx& wtxNew, CAmount nValue = (1*COIN));

opcodetype getOpcodeFromString(std::string input) {
    if (input == "OP_MINT") return OP_MINT;
	else if (input == "OP_DESTROY") return OP_DESTROY;
	else if (input == "OP_DROPLET") return OP_DROPLET;
	else if (input == "OP_REWARD_DYNODE") return OP_REWARD_DYNODE;
	else if (input == "OP_REWARD_MINING") return OP_REWARD_MINING;
	else if (input == "OP_STERILIZE") return OP_STERILIZE;
	else if (input == "OP_REALLOW") return OP_REALLOW;
	else if (input == "OP_FLUID_DEACTIVATE") return OP_FLUID_DEACTIVATE;
	else if (input == "OP_FLUID_REACTIVATE") return OP_FLUID_REACTIVATE;
	else if (input == "OP_INVEST") return OP_INVEST;
	else return OP_RETURN;
	
	return OP_RETURN;
};

/* Pretty pointless function, but - meh */
UniValue stringtohex(const UniValue& params, bool fHelp)
{
	std::string result;

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "stringtohex \"string\"\n"
            "\nConvert String to Hexadecimal Format\n"
            "\nArguments:\n"
            "1. \"string\"         (string, required) String that has to be converted to hex.\n"
            "\nExamples:\n"
            + HelpExampleCli("stringtohex", "\"Hello World!\"")
            + HelpExampleRpc("stringtohex", "\"Hello World!\"")
        );
	
	result = params[0].get_str();
	
	fluid.ConvertToHex(result);
	return result;
}

UniValue getrawpubkey(const UniValue& params, bool fHelp)
{
    UniValue ret(UniValue::VOBJ);

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getrawpubkey \"address\"\n"
            "\nGet (un)compressed raw public key of an address of the wallet\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The Dynamic Address from which the pubkey is to recovered.\n"
            "\nExamples:\n"
            + HelpExampleCli("burndynamic", "123.456")
            + HelpExampleRpc("burndynamic", "123.456")
        );

    CDynamicAddress address(params[0].get_str()); bool isValid = address.IsValid();

    if (isValid)
    {
        CTxDestination dest = address.Get();
        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("pubkey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
	} else {
		ret.push_back(Pair("errors", "Dynamic address is not valid!"));
	}
	
    return ret;
}

UniValue burndynamic(const UniValue& params, bool fHelp)
{
 	CWalletTx wtx;

    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "burndynamic \"amount\"\n"
            "\nSend coins to be burnt (destroyed) onto the Dynamic Network\n"
            "\nArguments:\n"
            "1. \"account\"         (numeric or string, required) The amount of coins to be minted.\n"
            "\nExamples:\n"
            + HelpExampleCli("burndynamic", "123.456")
            + HelpExampleRpc("burndynamic", "123.456")
        );

    EnsureWalletIsUnlocked();   
	
	CAmount nAmount = AmountFromValue(params[0]);
	
	if (nAmount <= 0)
		throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for destruction");
	
	std::string result = std::to_string(nAmount);
    fluid.ConvertToHex(result);
    
    CScript destroyScript = CScript() << OP_DESTROY << ParseHex(result);
    
    SendCustomTransaction(destroyScript, wtx, nAmount);

    return wtx.GetHash().GetHex();
}

opcodetype negatif = OP_RETURN;

UniValue sendfluidtransaction(const UniValue& params, bool fHelp)
{
	CScript finalScript;

    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "sendfluidtransaction \"OP_MINT || OP_DESTROY || OP_DROPLET || OP_REWARD_DYNODE || OP_REWARD_MINING || OP_STERILIZE || OP_FLUID_DEACTIVATE || OP_FLUID_REACTIVATE\" \"hexstring\"\n"
            "\Send Fluid transactions to the network\n"
            "\nArguments:\n"
            "1. \"opcode\"  (string, required) The Fluid operation to be executed.\n"
            "2. \"hexstring\" (string, required) The token for that opearation.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendfluidtransaction", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
            + HelpExampleRpc("sendfluidtransaction", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\", \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
        );

    EnsureWalletIsUnlocked();
    opcodetype opcode = getOpcodeFromString(params[0].get_str());
    
	if (negatif == opcode)
		throw std::runtime_error("OP_CODE is either not a Fluid OP_CODE or is invalid");

    if(!IsHex(params[1].get_str()))
		throw std::runtime_error("Hex isn't even valid!");    
	else
		finalScript = CScript() << opcode << ParseHex(params[1].get_str());

	std::string message;

    if(!fluid.CheckIfQuorumExists(ScriptToAsmStr(finalScript), message))
		throw std::runtime_error("Instruction does not meet required quorum for validity");
	
	CWalletTx wtx;
    SendCustomTransaction(finalScript, wtx);

    return wtx.GetHash().GetHex();
}

UniValue signtoken(const UniValue& params, bool fHelp)
{
	std::string result;
	
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "signtoken \"address\" \"tokenkey\"\n"
            "\nSign a Fluid Protocol Token\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The Dynamic Address which will be used to sign.\n"
            "2. \"tokenkey\"         (string, required) The token which has to be initially signed\n"
            "\nExamples:\n"
            + HelpExampleCli("signtoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
            + HelpExampleRpc("signtoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
        );
     
    CDynamicAddress address(params[0].get_str());
    if (!address.IsValid())
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dynamic address");
	
	if (!fluid.IsGivenKeyMaster(address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not Fluid Protocol Sovreign address");
	
    if (!fluid.InitiateFluidVerify(address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not possessed by wallet!");

	std::string r = params[1].get_str();

    if(!IsHex(r))
		throw std::runtime_error("Hex isn't even valid! Cannot process ahead...");

	fluid.ConvertToString(r);
	
	if (!fluid.GenericSignMessage(r, result, address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Message signing failed");
    
    return result;
}

UniValue verifyquorum(const UniValue& params, bool fHelp)
{
	std::string message;
	
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "verifyquorum \"tokenkey\"\n"
            "\nVerify if the token provided has required quorum\n"
            "\nArguments:\n"
            "1. \"tokenkey\"         (string, required) The token which has to be initially signed\n"
            "\nExamples:\n"
            + HelpExampleCli("consenttoken", "\"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
            + HelpExampleRpc("consenttoken", "\"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
        );
	
    if (!fluid.CheckNonScriptQuorum(params[0].get_str(), message, false))
		throw std::runtime_error("Instruction does not meet minimum quorum for validity");

    return "Quorum is present!";
}

UniValue consenttoken(const UniValue& params, bool fHelp)
{
	std::string result;

    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "consenttoken \"address\" \"tokenkey\"\n"
            "\nGive consent to a Fluid Protocol Token as a second party\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The Dynamic Address which will be used to give consent.\n"
            "2. \"tokenkey\"         (string, required) The token which has to be been signed by one party\n"
            "\nExamples:\n"
            + HelpExampleCli("consenttoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
            + HelpExampleRpc("consenttoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
        );
	
    CDynamicAddress address(params[0].get_str());
    if (!address.IsValid())
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dynamic address");
	
	int x;
	
	if (!IsHex(params[1].get_str()))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Hex string is invalid! Token incorrect");
	
	if (!fluid.IsGivenKeyMaster(address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not Fluid Protocol Sovreign address");
	
    if (!fluid.InitiateFluidVerify(address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not possessed by wallet!");

	std::string message;

    if (!fluid.CheckNonScriptQuorum(params[1].get_str(), message, true))
		throw std::runtime_error("Instruction does not meet minimum quorum for validity");

	if (!fluid.GenericConsentMessage(params[1].get_str(), result, address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Message signing failed");
	
	if (!fluid.CheckNonScriptQuorum(result, message, false))
		throw std::runtime_error("Quorum Signature cannot be from the same address twice");
	
	return result;
}


/* Pretty pointless function, but - meh */
UniValue stringtohash(const UniValue& params, bool fHelp)
{
	std::string result;

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "stringtohash \"string\"\n"
            "\nHashes string to default hashing algorithm\n"
            "\nArguments:\n"
            "1. \"string\"         (string, required) String that has to be hashed.\n"
            "\nExamples:\n"
            + HelpExampleCli("stringtohex", "\"Hello World!\"")
            + HelpExampleRpc("stringtohex", "\"Hello World!\"")
        );
	
	result = params[0].get_str();
	uint256 hashed = Hash(result.begin(), result.end());
	return hashed.ToString();
}

UniValue fluidcommandshistory(const UniValue& params, bool fHelp) {
	GetLastBlockIndex(chainActive.Tip());
	CBlockIndex* pindex = chainActive.Tip();
	CFluidEntry fluidIndex = pindex->fluidParams;
	StringVector transactionRecord = fluidIndex.fluidHistory;

	UniValue obj(UniValue::VOBJ);

    for (const std::string& existingRecord : transactionRecord) {
		obj.push_back(Pair("fluidCommand", existingRecord)); // We will make it a pair with timestamp later
    }
    
	return obj;
}

UniValue sterilizeaddresslist(const UniValue& params, bool fHelp) {
	GetLastBlockIndex(chainActive.Tip());
	CBlockIndex* pindex = chainActive.Tip();
	CFluidEntry fluidIndex = pindex->fluidParams;
	HashVector bannedDatabase = fluidIndex.bannedAddresses;
	
	UniValue obj(UniValue::VOBJ);

    for (const uint256& offendingHash : bannedDatabase) {
		obj.push_back(Pair("bannedAddress", offendingHash.ToString()));
    }
    
	return obj;
}

UniValue lockdynamic(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "lockdynamic \"string\"\n"
            "\nInvest Dynamic into a Fixed Deposit\n"
            "\nArguments:\n"
            "1. \"string\"         (string, required) String that has to be hashed.\n"
            "\nExamples:\n"
            + HelpExampleCli("stringtohex", "\"Hello World!\"")
            + HelpExampleRpc("stringtohex", "\"Hello World!\"")
		);
        
        
}

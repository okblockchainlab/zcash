// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"
#include "clientversion.h"
#include "rpcclient.h"
#include "rpcprotocol.h"
#include "util.h"
#include "utilstrencodings.h"
#include "rpcserver.h"

#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>
#include <stdio.h>

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include "support/events.h"

#include <univalue.h>
#include "com_okcoin_vault_jni_zcash_CZcashOk.h"


#define LOG(format, ...) printf(format, ##__VA_ARGS__)

#define LOG_DEBUG(format, ...) printf(format, ##__VA_ARGS__)

static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;
static const int CONTINUE_EXECUTION=-1;

std::string HelpMessageCli()
{
    std::string strUsage;
    strUsage += HelpMessageGroup(_("Options:"));
    strUsage += HelpMessageOpt("-?", _("This help message"));
    strUsage += HelpMessageOpt("-conf=<file>", strprintf(_("Specify configuration file (default: %s)"), "zcash.conf"));
    strUsage += HelpMessageOpt("-datadir=<dir>", _("Specify data directory"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test network"));
    strUsage += HelpMessageOpt("-regtest", _("Enter regression test mode, which uses a special chain in which blocks can be "
                                             "solved instantly. This is intended for regression testing tools and app development."));
    strUsage += HelpMessageOpt("-rpcconnect=<ip>", strprintf(_("Send commands to node running on <ip> (default: %s)"), "127.0.0.1"));
    strUsage += HelpMessageOpt("-rpcport=<port>", strprintf(_("Connect to JSON-RPC on <port> (default: %u or testnet: %u)"), 8232, 18232));
    strUsage += HelpMessageOpt("-rpcwait", _("Wait for RPC server to start"));
    strUsage += HelpMessageOpt("-rpcuser=<user>", _("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcpassword=<pw>", _("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcclienttimeout=<n>", strprintf(_("Timeout in seconds during HTTP requests, or 0 for no timeout. (default: %d)"), DEFAULT_HTTP_CLIENT_TIMEOUT));
    strUsage += HelpMessageOpt("-stdin", _("Read extra arguments from standard input, one per line until EOF/Ctrl-D (recommended for sensitive information such as passphrases)"));

    return strUsage;
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
            std::runtime_error(msg)
    {}

};

//
// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
//
static int AppInitRPC(int argc, char* argv[])
{
    static_assert(CONTINUE_EXECUTION != EXIT_FAILURE,
                  "CONTINUE_EXECUTION should be different from EXIT_FAILURE");
    static_assert(CONTINUE_EXECUTION != EXIT_SUCCESS,
                  "CONTINUE_EXECUTION should be different from EXIT_SUCCESS");
    //
    // Parameters
    //
    //ParseParameters(argc, argv);

    if (!boost::filesystem::is_directory(GetDataDir(false))) {
        fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
        return EXIT_FAILURE;
    }

    try {
        ;//ReadConfigFile(mapArgs, mapMultiArgs);
    } catch (const std::exception& e) {
        fprintf(stderr,"Error reading configuration file: %s\n", e.what());
        return EXIT_FAILURE;
    }

    // Check for -testnet or -regtest parameter (BaseParams() calls are only valid after this clause)
    if (!SelectBaseParamsFromCommandLine()) {
        fprintf(stderr, "Error: Invalid combination of -regtest and -testnet.\n");
        return EXIT_FAILURE;
    }

    if (GetBoolArg("-rpcssl", false))
    {
        fprintf(stderr, "Error: SSL mode for RPC (-rpcssl) is no longer supported.\n");
        return EXIT_FAILURE;
    }
    return CONTINUE_EXECUTION;
}


/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    std::string body;
};

const char *http_errorstring(int code)
{
    switch(code) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
        case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
#endif
        default:
            return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}
#endif

UniValue CallRPC(const std::string& strMethod, const UniValue& params)
{
    std::string host = GetArg("-rpcconnect", "127.0.0.1");
    int port = GetArg("-rpcport", BaseParams().RPCPort());

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_timeout(evcon.get(), GetArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == NULL)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    // Get credentials
    std::string strRPCUserColonPass;
    if (mapArgs["-rpcpassword"] == "") {
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetAuthCookie(&strRPCUserColonPass)) {
            throw std::runtime_error(strprintf(
                    _("Could not locate RPC credentials. No authentication cookie could be found,\n"
                      "and no rpcpassword is set in the configuration file (%s)."),
                    GetConfigFile().string().c_str()));

        }
    } else {
        strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
    }

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequest(strMethod, params, 1);
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, "/");
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw std::runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}


CRPCTable rpcTalbe;

UniValue CommandLineRPC(std::string strMethod, std::vector<std::string> &args)
{
    printf("enter CommandLineRPC \n\n");
    std::string strPrint;
    UniValue result;
    int nRet = 0;
    try {
        UniValue params = RPCConvertValues(strMethod, args);

        printf("before prcTalbe \n");
        const UniValue reply = rpcTalbe.execute(strMethod, params);
        printf("end prcTalbe");
        //rpcTalbe[strMethod]
        // Parse reply
        result = find_value(reply, "result");
        const UniValue& error  = find_value(reply, "error");

        if (!error.isNull()) {
            // Error
            int code = error["code"].get_int();
            strPrint = "error: " + error.write();
            nRet = abs(code);
            if (error.isObject())
            {
                UniValue errCode = find_value(error, "code");
                UniValue errMsg  = find_value(error, "message");
                strPrint = errCode.isNull() ? "" : "error code: "+errCode.getValStr()+"\n";

                if (errMsg.isStr())
                    strPrint += "error message:\n"+errMsg.get_str();
            }
        } else {
            // Result
            if (result.isNull())
                strPrint = "";
            else if (result.isStr()) {


                strPrint = result.get_str();
                printf("result.isStr %s \n", strPrint.c_str());
            }
            else
                strPrint = result.write(2);
        }
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
        nRet = EXIT_FAILURE;
    }
    catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRPC()");
        throw;
    }

    if (strPrint != "") {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }

    return result;
}

void Test_rpc()
{
    std::string strPrint;
    std::string strMethod = "ok_wwftest";
    std::vector<std::string> params_formt;
    params_formt.push_back("param1");
    params_formt.push_back("param2");
    params_formt.push_back("param3");

    UniValue params ;//= RPCConvertValues(strMethod, params_formt);

    try {
        const UniValue reply = CallRPC(strMethod, params);

        // Parse reply
        const UniValue& result = find_value(reply, "result");
        const UniValue& error  = find_value(reply, "error");

        if (!error.isNull()) {
            // Error
            int code = error["code"].get_int();
            if ( code == RPC_IN_WARMUP)
                throw CConnectionFailed("server in warmup");
            strPrint = "error: " + error.write();
            int nRet = abs(code);
            if (error.isObject())
            {
                UniValue errCode = find_value(error, "code");
                UniValue errMsg  = find_value(error, "message");
                strPrint = errCode.isNull() ? "" : "error code: "+errCode.getValStr()+"\n";

                if (errMsg.isStr())
                    strPrint += "error message:\n"+errMsg.get_str();
            }
        } else {
            // Result
            if (result.isNull())
                strPrint = "";
            else if (result.isStr())
                strPrint = result.get_str();
            else
                strPrint = result.write(2);
        }

    }
    catch (const CConnectionFailed&) {
        throw;
    }

    printf("params:%s \n", strPrint.c_str());

}

bool g_AppInitRPC = false;
UniValue EXEMethod(const std::string strMethod,  std::vector <std::string> &params_formt){

    UniValue result("");
    try {
        if (!g_AppInitRPC)
        {
            //SelectBaseParams(CBaseChainParams::TESTNET);
            char params[2][15] = {"java", "ok_getAddress"};
            int ret = AppInitRPC(2, (char**)params);
            if (ret != CONTINUE_EXECUTION)
                return result;
        }
        g_AppInitRPC = true;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRPC()");
        return result;
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInitRPC()");
        return result;
    }

    try {
        result = CommandLineRPC(strMethod, params_formt);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "CommandLineRPC()");
    } catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRPC()");
    }

    return result;

}

std::string getAddress(std::string privateKey) {

    std::string strMethod = "ok_getAddress";
    std::vector <std::string> params_formt;
    params_formt.push_back(privateKey);

    UniValue result = EXEMethod(strMethod, params_formt);

    std::string taddr;
    if (result.isNull() || !result.isStr())
        taddr = "";
    else
        taddr = result.get_str();


    LOG("getAddress t_addre:%s\n", taddr.c_str());
    return taddr;
}

std::string produceUnsignedTx(std::string targetAddress, std::string amount){

    std::string strMethod = "ok_produceUnsignedTx";
    std::vector <std::string> params_formt;
    params_formt.push_back(targetAddress);
    params_formt.push_back(amount);

    LOG(" enter produceUnsignedTx :address:%s\n", targetAddress.c_str());
    UniValue result = EXEMethod(strMethod, params_formt);
    LOG(" out produceUnsignedTx \n");
    std::string txHex;
    if (result.isNull() || !result.isStr())
        txHex = "";
    else
        txHex = result.get_str();


    LOG("produceUnsignedTx txHex:%s\n", txHex.c_str());
    return txHex;
}

std::string signTransaction(std::string unsignedTx){

    std::string strMethod = "ok_signTransaction";
    std::vector <std::string> params_formt;
    params_formt.push_back(unsignedTx);

    UniValue result = EXEMethod(strMethod, params_formt);
    std::string txHexSign;

    if (result.isNull() || !result.isStr())
        txHexSign = "";
    else
        txHexSign = result.get_str();

    LOG("signTransaction txHexSign:%s\n", txHexSign.c_str());
    return txHexSign;
}


/*
 * Class:     com_okcoin_vault_jni_CZcashj
 * Method:    getAddress
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_okcoin_vault_jni_CZcashj_getAddress
        (JNIEnv *env, jobject ob, jstring privKey){

    const char*  str = env->GetStringUTFChars(privKey, 0);

    //char tmpstr[] = "return string succeeded";

    std::string tmpstr = getAddress(str);
    jstring rtstr = env->NewStringUTF(tmpstr.c_str());
    return rtstr;
}

/*
 * Class:     com_okcoin_vault_jni_CZcashj
 * Method:    produceUnsignedTx
 * Signature: (Ljava/lang/String;Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_okcoin_vault_jni_CZcashj_produceUnsignedTx
        (JNIEnv *env, jobject ob, jstring addr, jstring amount){


    const char*  strAddress = env->GetStringUTFChars(addr, 0);
    const char*  strAmount = env->GetStringUTFChars(amount, 0);

    std::string tmpstr = produceUnsignedTx(strAddress, strAmount);
    //nOutSize是BYTE数组的长度 BYTE pData[]

    int nOutSize = tmpstr.size();
    jbyte *by = (jbyte*)tmpstr.c_str();
    jbyteArray jarray = env->NewByteArray(nOutSize);
    env->SetByteArrayRegion(jarray, 0, nOutSize, by);

    return jarray;

}

/*
 * Class:     com_okcoin_vault_jni_CZcashj
 * Method:    signTransaction
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_okcoin_vault_jni_CZcashj_signTransaction
        (JNIEnv *env, jobject ob, jbyteArray transacHex){
    char* data = (char*)env->GetByteArrayElements(transacHex, 0);



    std::string tmpstr = signTransaction(data);


    int nOutSize = tmpstr.size();
    jbyte *by = (jbyte*)tmpstr.c_str();
    jbyteArray jarray = env->NewByteArray(nOutSize);
    env->SetByteArrayRegion(jarray, 0, nOutSize, by);

    return jarray;

}

/*
 * Class:     com_okcoin_vault_jni_zcash_CZcashOk
 * Method:    execute
 * Signature: (Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_com_okcoin_vault_jni_zcash_CZcashOk_execute
        (JNIEnv *env, jclass ob, jstring netType, jstring params)
{

    const char*  netTypes = env->GetStringUTFChars(netType, 0);
    const char*  strParams = env->GetStringUTFChars(params, 0);



    std::vector<std::string> vArgs;
    boost::split(vArgs, strParams, boost::is_any_of(" \t"));

    std::string strMethod = vArgs[0];

    for (int i=0; i<vArgs.size(); i++){
        printf("%d:%s \n", i, vArgs[i].c_str());
    }

    std::vector<std::string> paramEn  = std::vector<std::string>(vArgs.begin()+1, vArgs.end());
    UniValue ret = EXEMethod(strMethod, paramEn);

    std::list<std::string> kvList;
    std::string context;
    ret.feedStringList(kvList, context);
    int len = kvList.size();

    jclass cls = env->FindClass("java/lang/Object");
    jobjectArray mjobjectArray = (jobjectArray)env->NewObjectArray(len, cls, NULL);

    int i=0;
    for(std::list<std::string>::iterator it = kvList.begin(); it != kvList.end(); it++, i++){
        jstring mystring=env->NewStringUTF((*it).c_str());
        env->SetObjectArrayElement(mjobjectArray,
                                   i,(jobject)mystring);
    }

    return mjobjectArray;

}





//test for main

int main(int argc, char* argv[])
{

    return 0;

}



// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "com_okcoin_vault_jni_zcash_CZcashOk.h"

#include <stdio>
#include <string>
/*
 * Class:     com_okcoin_vault_jni_CZcashOk
 * Method:    execute
 * Signature: (Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_com_okcoin_vault_jni_CZcashOk_execute
        (JNIEnv *env, jclass ob, jstring netType, jstring params)
{

    const char*  netTypes = env->GetStringUTFChars(netType, 0);
    const char*  strParams = env->GetStringUTFChars(params, 0);

    printf("asdfadf");

    jclass cls = env->FindClass("java/lang/Object");
    jobjectArray mjobjectArray = (jobjectArray)env->NewObjectArray(1, cls, NULL);


    return mjobjectArray;

}



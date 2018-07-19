
#include "com_okcoin_vault_jni_zcash_CZcashOk.h"

#include <string>
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
    


    jclass cls = env->FindClass("java/lang/Object");
    jobjectArray mjobjectArray = (jobjectArray)env->NewObjectArray(1, cls, NULL);



    return mjobjectArray;

}





//test for main

int main(int argc, char* argv[])
{




    return 0;

}



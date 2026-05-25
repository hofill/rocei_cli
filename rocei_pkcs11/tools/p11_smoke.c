#include "../src/pkcs11_platform.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef CK_RV (*get_function_list_fn)(CK_FUNCTION_LIST_PTR_PTR);
typedef CK_RV (*set_pace_credential_fn)(CK_SLOT_ID, CK_ULONG, CK_UTF8CHAR_PTR,
                                        CK_ULONG, CK_BBOOL);

static void print_rv(const char *label, CK_RV rv) {
    printf("%-24s 0x%08lX\n", label, (unsigned long)rv);
}

static CK_RV find_first(CK_FUNCTION_LIST_PTR f, CK_SESSION_HANDLE session,
                        CK_OBJECT_CLASS cls, CK_OBJECT_HANDLE_PTR out) {
    CK_ATTRIBUTE templ = {
        .type = CKA_CLASS,
        .pValue = &cls,
        .ulValueLen = sizeof(cls),
    };
    CK_RV rv = f->C_FindObjectsInit(session, &templ, 1);
    if (rv != CKR_OK) return rv;
    CK_ULONG count = 0;
    rv = f->C_FindObjects(session, out, 1, &count);
    CK_RV final_rv = f->C_FindObjectsFinal(session);
    if (rv != CKR_OK) return rv;
    if (final_rv != CKR_OK) return final_rv;
    return count == 1 ? CKR_OK : CKR_OBJECT_HANDLE_INVALID;
}

int main(int argc, char **argv) {
    const char *module_path = "./rocei_pkcs11.dylib";
    int do_sign = 0;
    int set_pace_pin = 0;
    size_t hash_len = 32;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sign") == 0) {
            do_sign = 1;
        } else if (strcmp(argv[i], "--pace-pin") == 0) {
            set_pace_pin = 1;
        } else if (strcmp(argv[i], "--hash-len") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long n = strtoul(argv[++i], &end, 0);
            if (!end || *end || n == 0 || n > 128) {
                fprintf(stderr, "invalid --hash-len value\n");
                return 1;
            }
            hash_len = (size_t)n;
        } else {
            module_path = argv[i];
        }
    }

    void *lib = dlopen(module_path, RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    get_function_list_fn get_function_list =
        (get_function_list_fn)dlsym(lib, "C_GetFunctionList");
    if (!get_function_list) {
        fprintf(stderr, "C_GetFunctionList not found\n");
        return 1;
    }

    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV rv = get_function_list(&f);
    print_rv("C_GetFunctionList", rv);
    if (rv != CKR_OK) return 1;

    rv = f->C_Initialize(NULL_PTR);
    print_rv("C_Initialize", rv);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) return 1;

    if (set_pace_pin) {
        set_pace_credential_fn set_pace =
            (set_pace_credential_fn)dlsym(lib, "C_SetPaceCredential");
        if (!set_pace) {
            printf("C_SetPaceCredential    unavailable\n");
        } else {
            char *pace_pin = getpass("PACE PIN: ");
            if (!pace_pin || !*pace_pin) {
                printf("empty PACE PIN; skipping C_SetPaceCredential\n");
            } else {
                CK_ULONG pace_len = (CK_ULONG)strlen(pace_pin);
                rv = set_pace(0, 3, (CK_UTF8CHAR_PTR)pace_pin, pace_len, CK_FALSE);
                memset(pace_pin, 0, pace_len);
                print_rv("C_SetPaceCredential", rv);
            }
        }
    }

    CK_ULONG slot_count = 0;
    rv = f->C_GetSlotList(CK_TRUE, NULL_PTR, &slot_count);
    print_rv("C_GetSlotList count", rv);
    printf("token slots              %lu\n", (unsigned long)slot_count);
    if (rv != CKR_OK || slot_count == 0) {
        f->C_Finalize(NULL_PTR);
        return rv == CKR_OK ? 0 : 1;
    }

    CK_SLOT_ID *slots = calloc(slot_count, sizeof(CK_SLOT_ID));
    if (!slots) return 1;
    rv = f->C_GetSlotList(CK_TRUE, slots, &slot_count);
    print_rv("C_GetSlotList data", rv);
    if (rv != CKR_OK) return 1;

    CK_SESSION_HANDLE session = 0;
    rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
    print_rv("C_OpenSession", rv);
    if (rv != CKR_OK) return 1;

    CK_OBJECT_HANDLE cert = 0;
    rv = find_first(f, session, CKO_CERTIFICATE, &cert);
    print_rv("find cert", rv);
    if (rv == CKR_OK) {
        CK_ATTRIBUTE value = {.type = CKA_VALUE, .pValue = NULL_PTR, .ulValueLen = 0};
        rv = f->C_GetAttributeValue(session, cert, &value, 1);
        print_rv("cert CKA_VALUE", rv);
        if (rv == CKR_OK)
            printf("cert bytes               %lu\n", (unsigned long)value.ulValueLen);
    }

    if (do_sign) {
        char *pin = getpass("PIN: ");
        if (!pin || !*pin) {
            printf("empty PIN; skipping login/sign\n");
            goto done;
        }
        rv = f->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin));
        size_t pin_len = strlen(pin);
        memset(pin, 0, pin_len);
        print_rv("C_Login", rv);
        if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) {
            CK_OBJECT_HANDLE key = 0;
            rv = find_first(f, session, CKO_PRIVATE_KEY, &key);
            print_rv("find private key", rv);
            if (rv == CKR_OK) {
                CK_MECHANISM mech = {.mechanism = CKM_ECDSA, .pParameter = NULL_PTR, .ulParameterLen = 0};
                rv = f->C_SignInit(session, &mech, key);
                print_rv("C_SignInit", rv);
                if (rv == CKR_OK) {
                    CK_BYTE hash[128] = {0};
                    CK_BYTE sig[132] = {0};
                    CK_ULONG sig_len = sizeof(sig);
                    for (size_t i = 0; i < hash_len; i++)
                        hash[i] = (CK_BYTE)(i + 1);
                    printf("hash bytes               %lu\n", (unsigned long)hash_len);
                    rv = f->C_Sign(session, hash, (CK_ULONG)hash_len, sig, &sig_len);
                    print_rv("C_Sign", rv);
                    if (rv == CKR_OK)
                        printf("signature bytes          %lu\n", (unsigned long)sig_len);
                }
            }
        }
    } else {
        printf("signing skipped; pass --sign to prompt for PIN\n");
    }

done:
    f->C_CloseSession(session);
    f->C_Finalize(NULL_PTR);
    free(slots);
    dlclose(lib);
    return 0;
}

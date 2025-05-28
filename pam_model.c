#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

/*
 * Credenciais de autenticação
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/*
 * Função de autenticação
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    char input[9];         // Buffer para armazenar a entrada do usuário
    char correct_date[9];  // Buffer para armazenar a data correta
    time_t t;
    struct tm *tm_info;
    struct pam_conv *conv;
    struct pam_response *resp = NULL;

    // Obtém a data atual
    time(&t);
    tm_info = localtime(&t);
    strftime(correct_date, sizeof(correct_date), "%d%m%Y", tm_info); // Formata a data como DDMMAAAA

    // Obtém o método de conversação do PAM
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || !conv || !conv->conv)
    {
        pam_syslog(pamh, LOG_ERR, "Erro ao obter o metodo de conversacao do PAM.");
        return PAM_AUTH_ERR;
    }

    // Solicita a data ao usuário
    const char *msg = "\nInsira a data de hoje para a verificacao de duas etapas (DDMMAAAA): ";
    const struct pam_message msg_struct = { PAM_PROMPT_ECHO_ON, msg };
    const struct pam_message *msg_arr[] = { &msg_struct };

    int retval = conv->conv(1, msg_arr, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS || !resp || !resp->resp)
    {
        pam_syslog(pamh, LOG_ERR, "Falha ao obter resposta do usuario.");
        return PAM_AUTH_ERR;
    }

    // Copia a entrada do usuário para evitar buffer overflow
    strncpy(input, resp->resp, sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';

    // Remove possíveis quebras de linha no final da entrada
    input[strcspn(input, "\n")] = '\0';

    // Verifica se a data inserida está correta
    if (strcmp(input, correct_date) == 0)
    {
        const struct pam_message success_msg = { PAM_TEXT_INFO, "Autenticacao bem-sucedida." };
        const struct pam_message *success_arr[] = { &success_msg };
        conv->conv(1, success_arr, &resp, conv->appdata_ptr);

        pam_syslog(pamh, LOG_NOTICE, "Autenticacao bem-sucedida.");
        return PAM_SUCCESS;
    }
    else
    {
        const struct pam_message fail_msg = { PAM_TEXT_INFO, "Falha na autenticacao: Data incorreta." };
        const struct pam_message *fail_arr[] = { &fail_msg };
        conv->conv(1, fail_arr, &resp, conv->appdata_ptr);

        pam_syslog(pamh, LOG_NOTICE, "Falha na autenticacao: Data incorreta.");
        return PAM_AUTH_ERR;
    }
}

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

/*
 * Credenciais de autentica��o
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/*
 * Fun��o de autentica��o
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    char input[9];         // Buffer para armazenar a entrada do usu�rio
    char correct_date[9];  // Buffer para armazenar a data correta
    time_t t;
    struct tm *tm_info;
    struct pam_conv *conv;
    struct pam_response *resp = NULL;

    // Obt�m a data atual
    time(&t);
    tm_info = localtime(&t);
    strftime(correct_date, sizeof(correct_date), "%d%m%Y", tm_info); // Formata a data como DDMMAAAA

    // Obt�m o m�todo de conversa��o do PAM
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || !conv || !conv->conv)
    {
        pam_syslog(pamh, LOG_ERR, "Erro ao obter o m�todo de conversa��o do PAM.");
        return PAM_AUTH_ERR;
    }

    // Solicita a data ao usu�rio
    const char *msg = "Insira a data de hoje para a verifica��o (DDMMAAAA): ";
    const struct pam_message msg_struct = { PAM_PROMPT_ECHO_ON, msg };
    const struct pam_message *msg_arr[] = { &msg_struct };

    int retval = conv->conv(1, msg_arr, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS || !resp || !resp->resp)
    {
        pam_syslog(pamh, LOG_ERR, "Falha ao obter resposta do usu�rio.");
        return PAM_AUTH_ERR;
    }

    // Copia a entrada do usu�rio para evitar buffer overflow
    strncpy(input, resp->resp, sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';

    // Remove poss�veis quebras de linha no final da entrada
    input[strcspn(input, "\n")] = '\0';

    // Libera a mem�ria alocada para a resposta
    free(resp->resp);
    free(resp);

    // Verifica se a data inserida est� correta
    if (strcmp(input, correct_date) == 0)
    {
        pam_syslog(pamh, LOG_NOTICE, "Autentica��o bem-sucedida.");
        return PAM_SUCCESS;
    }
    else
    {
        pam_syslog(pamh, LOG_NOTICE, "Falha na autentica��o: Data incorreta.");
        return PAM_AUTH_ERR;
    }
}

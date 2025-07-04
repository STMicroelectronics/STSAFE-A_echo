/**
 ******************************************************************************
 * \file    		main.c
 * \author  		CS application team
 ******************************************************************************
 *           			COPYRIGHT 2022 STMicroelectronics
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

/* Includes ------------------------------------------------------------------*/

#include "Drivers/delay_ms/delay_ms.h"
#include "Drivers/rng/rng.h"
#include "Drivers/uart/uart.h"
#include "stselib.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defines -------------------------------------------------------------------*/

#define PRINT_CLEAR_SCREEN "\x1B[1;1H\x1B[2J"
#define PRINT_BLINK "\x1B[5m"
#define PRINT_UNDERLINE "\x1B[4m"
#define PRINT_BELL "\a"
#define PRINT_BOLD "\x1B[1m"
#define PRINT_ITALIC "\x1B[3m"
#define PRINT_RESET "\x1B[0m"
#ifdef DISABLE_PRINT_COLOR
#define PRINT_BLACK ""   /* Black */
#define PRINT_RED ""     /* Red */
#define PRINT_GREEN ""   /* Green */
#define PRINT_YELLOW ""  /* Yellow */
#define PRINT_BLUE ""    /* Blue */
#define PRINT_MAGENTA "" /* Magenta */
#define PRINT_CYAN ""    /* Cyan */
#define PRINT_WHITE ""   /* White */
#else
#define PRINT_BLACK "\x1B[30m"   /* Black */
#define PRINT_RED "\x1B[31m"     /* Red */
#define PRINT_GREEN "\x1B[32m"   /* Green */
#define PRINT_YELLOW "\x1B[33m"  /* Yellow */
#define PRINT_BLUE "\x1B[34m"    /* Blue */
#define PRINT_MAGENTA "\x1B[35m" /* Magenta */
#define PRINT_CYAN "\x1B[36m"    /* Cyan */
#define PRINT_WHITE "\x1B[37m"   /* White */

#endif

#define AC_FREE 0x01
#define AC_HOST_CMAC 0x03
#define ENCRYPT_NO 0x00
#define ENCRYPT_RSP 0x01
#define ENCRYPT_CMD 0x02
#define ENCRYPT_BOTH 0x03

PLAT_UI8 command_AC_table[] = {
    /*  [ OP CODE ] [Access Condition]                             */
    0x00, AC_HOST_CMAC,        /* Echo                          */
    0x02, AC_HOST_CMAC,        /* Reset                         */
    0x04, AC_HOST_CMAC,        /* Decrement                     */
    0x05, AC_HOST_CMAC,        /* Read                          */
    0x06, AC_HOST_CMAC,        /* Update                        */
    0x08, AC_FREE,             /* --Reserved-- : Do not modify  */
    0x09, AC_HOST_CMAC,        /* Generate MAC                  */
    0x0A, AC_HOST_CMAC,        /* Verify MAC                    */
    0x0E, AC_HOST_CMAC,        /* Wrap local envelope           */
    0x0F, AC_HOST_CMAC,        /* Unwrap local envelope         */
    0x11, AC_HOST_CMAC,        /* Generate Key                  */
    0x15, AC_HOST_CMAC,        /* Get signature                 */
    0x16, AC_HOST_CMAC,        /* Generate signature            */
    0x17, AC_HOST_CMAC,        /* Verify signature              */
    0x18, AC_HOST_CMAC,        /* Establish key                 */
    0x1A, AC_HOST_CMAC,        /* Verify password               */
    0x1B, AC_HOST_CMAC,        /* Encrypt                       */
    0x1C, AC_HOST_CMAC,        /* Decrypt                       */
    0x1F, 0x00, AC_HOST_CMAC,  /* Start Hash                    */
    0x1F, 0x01, AC_HOST_CMAC,  /* Process Hash                  */
    0x1F, 0x02, AC_HOST_CMAC,  /* Finish Hash                   */
    0x1F, 0x03, AC_HOST_CMAC,  /* Start volatile KEK session    */
    0x1F, 0x04, AC_HOST_CMAC,  /* Establish symmetric keys      */
    0x1F, 0x05, AC_HOST_CMAC,  /* Confirm symmetric keys        */
    0x1F, 0x06, AC_HOST_CMAC,  /* Stop volatile KEK session     */
    0x1F, 0x07, AC_FREE,       /* Write host key V2 plaintext   */
    0x1F, 0x08, AC_FREE,       /* Write host key V2 wrapped     */
    0x1F, 0x09, AC_HOST_CMAC,  /* Write symmetric key wrapped   */
    0x1F, 0x0A, AC_HOST_CMAC,  /* Write public key              */
    0x1F, 0x0B, AC_HOST_CMAC,  /* Generate ECDHE key            */
    0x1F, 0x0C, AC_FREE,       /* --Reserved-- : Do not modify  */
    0x1F, 0x0D, AC_FREE,       /* --Reserved-- : Do not modify  */
    0x1F, 0x0E, AC_HOST_CMAC,  /* Generate challenge            */
    0x1F, 0x0F, AC_HOST_CMAC,  /* Verify entity signature       */
    0x1F, 0x10, AC_HOST_CMAC,  /* Derive keys                   */
    0x1F, 0x11, AC_HOST_CMAC,  /* Start encrypt                 */
    0x1F, 0x12, AC_HOST_CMAC,  /* Process encrypt               */
    0x1F, 0x13, AC_HOST_CMAC,  /* Finish encrypt                */
    0x1F, 0x14, AC_HOST_CMAC,  /* Start decrypt                 */
    0x1F, 0x15, AC_HOST_CMAC,  /* Process decrypt               */
    0x1F, 0x16, AC_HOST_CMAC,  /* Finish decrypt                */
    0x1F, 0x17, AC_HOST_CMAC,  /* Write symmetric key plaintext */
    0x1F, 0x18, AC_FREE,       /* Establish host key V2         */
    0x1F, 0x19, AC_HOST_CMAC,  /* Erase symmetric key slot      */
    0x1F, 0x1A, AC_HOST_CMAC}; /* Decompress public key         */

PLAT_UI8 command_encryption_table[] = {
    /*  [ OP CODE ] [Encryption]                                   */
    0x00, ENCRYPT_NO,       /* Echo                          */
    0x02, ENCRYPT_NO,       /* Reset                         */
    0x04, ENCRYPT_NO,       /* Decrement                     */
    0x05, ENCRYPT_NO,       /* Read                          */
    0x06, ENCRYPT_NO,       /* Update                        */
    0x08, ENCRYPT_NO,       /* --Reserved-- : Do not modify  */
    0x09, ENCRYPT_NO,       /* Generate MAC                  */
    0x0A, ENCRYPT_NO,       /* Verify MAC                    */
    0x0E, ENCRYPT_NO,       /* Wrap local envelope           */
    0x0F, ENCRYPT_NO,       /* Unwrap local envelope         */
    0x11, ENCRYPT_NO,       /* Generate Key                  */
    0x15, ENCRYPT_NO,       /* Get signature                 */
    0x16, ENCRYPT_NO,       /* Generate signature            */
    0x17, ENCRYPT_NO,       /* Verify signature              */
    0x18, ENCRYPT_NO,       /* Establish key                 */
    0x1A, ENCRYPT_NO,       /* Verify password               */
    0x1B, ENCRYPT_NO,       /* Encrypt                       */
    0x1C, ENCRYPT_NO,       /* Decrypt                       */
    0x1F, 0x00, ENCRYPT_NO, /* Start Hash                    */
    0x1F, 0x01, ENCRYPT_NO, /* Process Hash                  */
    0x1F, 0x02, ENCRYPT_NO, /* Finish Hash                   */
    0x1F, 0x03, ENCRYPT_NO, /* Start volatile KEK session    */
    0x1F, 0x04, ENCRYPT_NO, /* Establish symmetric keys      */
    0x1F, 0x05, ENCRYPT_NO, /* Confirm symmetric keys        */
    0x1F, 0x06, ENCRYPT_NO, /* Stop volatile KEK session     */
    0x1F, 0x07, ENCRYPT_NO, /* Write host key V2 plaintext   */
    0x1F, 0x08, ENCRYPT_NO, /* Write host key V2 wrapped     */
    0x1F, 0x09, ENCRYPT_NO, /* Write symmetric key wrapped   */
    0x1F, 0x0A, ENCRYPT_NO, /* Write public key              */
    0x1F, 0x0B, ENCRYPT_NO, /* Generate ECDHE key            */
    0x1F, 0x0C, ENCRYPT_NO, /* --Reserved-- : Do not modify  */
    0x1F, 0x0D, ENCRYPT_NO, /* --Reserved-- : Do not modify  */
    0x1F, 0x0E, ENCRYPT_NO, /* Generate challenge            */
    0x1F, 0x0F, ENCRYPT_NO, /* Verify entity signature       */
    0x1F, 0x10, ENCRYPT_NO, /* Derive keys                   */
    0x1F, 0x11, ENCRYPT_NO, /* Start encrypt                 */
    0x1F, 0x12, ENCRYPT_NO, /* Process encrypt               */
    0x1F, 0x13, ENCRYPT_NO, /* Finish encrypt                */
    0x1F, 0x14, ENCRYPT_NO, /* Start decrypt                 */
    0x1F, 0x15, ENCRYPT_NO, /* Process decrypt               */
    0x1F, 0x16, ENCRYPT_NO, /* Finish decrypt                */
    0x1F, 0x17, ENCRYPT_NO, /* Write symmetric key plaintext */
    0x1F, 0x18, ENCRYPT_NO, /* Establish host key V2         */
    0x1F, 0x19, ENCRYPT_NO, /* Erase symmetric key slot      */
    0x1F, 0x1A, ENCRYPT_NO, /* Decompress public key         */
};

//PLAT_UI8 command_AC_table[] = {
///*  [ OP CODE ] [Access Condition]                             */
//          0x00, AC_HOST_CMAC,      /* Echo                          */
//          0x02, AC_HOST_CMAC,      /* Reset                         */
//          0x04, AC_HOST_CMAC,      /* Decrement                     */
//          0x05, AC_HOST_CMAC,      /* Read                          */
//          0x06, AC_HOST_CMAC,      /* Update                        */
//          0x08, AC_FREE, 	  		/* --Reserved-- : Do not modify  */
//          0x09, AC_HOST_CMAC,      /* Generate MAC                  */
//          0x0A, AC_HOST_CMAC,      /* Verify MAC                    */
//          0x0E, AC_HOST_CMAC, 		/* Wrap local envelope           */
//          0x0F, AC_HOST_CMAC, 		/* Unwrap local envelope         */
//          0x11, AC_HOST_CMAC,      /* Generate Key                  */
//          0x15, AC_HOST_CMAC,      /* Get signature                 */
//          0x16, AC_HOST_CMAC,      /* Generate signature            */
//          0x17, AC_HOST_CMAC,      /* Verify signature              */
//          0x18, AC_HOST_CMAC,      /* Establish key                 */
//          0x1A, AC_HOST_CMAC,      /* Verify password               */
//          0x1B, AC_HOST_CMAC,      /* Encrypt                       */
//          0x1C, AC_HOST_CMAC,      /* Decrypt                       */
//    0x1F, 0x00, AC_HOST_CMAC,      /* Start Hash                    */
//    0x1F, 0x01, AC_HOST_CMAC,      /* Process Hash                  */
//    0x1F, 0x02, AC_HOST_CMAC,      /* Finish Hash                   */
//    0x1F, 0x03, AC_HOST_CMAC,      /* Start volatile KEK session    */
//    0x1F, 0x04, AC_HOST_CMAC,      /* Establish symmetric keys      */
//    0x1F, 0x05, AC_HOST_CMAC,      /* Confirm symmetric keys        */
//    0x1F, 0x06, AC_HOST_CMAC,      /* Stop volatile KEK session     */
//    0x1F, 0x07, AC_FREE,           /* Write host key V2 plaintext   */
//    0x1F, 0x08, AC_FREE,           /* Write host key V2 wrapped     */
//    0x1F, 0x09, AC_HOST_CMAC,      /* Write symmetric key wrapped   */
//    0x1F, 0x0A, AC_HOST_CMAC,      /* Write public key              */
//    0x1F, 0x0B, AC_HOST_CMAC,      /* Generate ECDHE key            */
//    0x1F, 0x0C, AC_FREE,           /* --Reserved-- : Do not modify  */
//    0x1F, 0x0D, AC_FREE,           /* --Reserved-- : Do not modify  */
//    0x1F, 0x0E, AC_HOST_CMAC,      /* Generate challenge            */
//    0x1F, 0x0F, AC_HOST_CMAC,      /* Verify entity signature       */
//    0x1F, 0x10, AC_HOST_CMAC,      /* Derive keys                   */
//    0x1F, 0x11, AC_HOST_CMAC,      /* Start encrypt                 */
//    0x1F, 0x12, AC_HOST_CMAC,      /* Process encrypt               */
//    0x1F, 0x13, AC_HOST_CMAC,      /* Finish encrypt                */
//    0x1F, 0x14, AC_HOST_CMAC,      /* Start decrypt                 */
//    0x1F, 0x15, AC_HOST_CMAC,      /* Process decrypt               */
//    0x1F, 0x16, AC_HOST_CMAC,      /* Finish decrypt                */
//    0x1F, 0x17, AC_HOST_CMAC,      /* Write symmetric key plaintext */
//    0x1F, 0x18, AC_FREE,      	   /* Establish host key V2         */
//    0x1F, 0x19, AC_HOST_CMAC,      /* Erase symmetric key slot      */
//    0x1F, 0x1A, AC_HOST_CMAC};     /* Decompress public key         */
//
//PLAT_UI8 command_encryption_table[] = {
///*  [ OP CODE ] [Encryption]                                   */
//          0x00, ENCRYPT_NO,   /* Echo                          */
//          0x02, ENCRYPT_NO,   /* Reset                         */
//          0x04, ENCRYPT_NO,   /* Decrement                     */
//          0x05, ENCRYPT_NO,   /* Read                          */
//          0x06, ENCRYPT_NO,   /* Update                        */
//          0x08, ENCRYPT_NO,   /* --Reserved-- : Do not modify  */
//          0x09, ENCRYPT_BOTH,   /* Generate MAC                  */
//          0x0A, ENCRYPT_BOTH,   /* Verify MAC                    */
//          0x0E, ENCRYPT_CMD,  /* Wrap local envelope           */
//          0x0F, ENCRYPT_RSP,  /* Unwrap local envelope         */
//          0x11, ENCRYPT_NO,   /* Generate Key                  */
//          0x15, ENCRYPT_NO,   /* Get signature                 */
//          0x16, ENCRYPT_NO,   /* Generate signature            */
//          0x17, ENCRYPT_NO,   /* Verify signature              */
//          0x18, ENCRYPT_NO,  /* Establish key                 */
//          0x1A, ENCRYPT_NO,   /* Verify password               */
//          0x1B, ENCRYPT_CMD,  /* Encrypt                       */
//          0x1C, ENCRYPT_RSP,  /* Decrypt                       */
//    0x1F, 0x00, ENCRYPT_NO,   /* Start Hash                    */
//    0x1F, 0x01, ENCRYPT_NO,   /* Process Hash                  */
//    0x1F, 0x02, ENCRYPT_NO,   /* Finish Hash                   */
//    0x1F, 0x03, ENCRYPT_NO,   /* Start volatile KEK session    */
//    0x1F, 0x04, ENCRYPT_NO,   /* Establish symmetric keys      */
//    0x1F, 0x05, ENCRYPT_NO,   /* Confirm symmetric keys        */
//    0x1F, 0x06, ENCRYPT_NO,   /* Stop volatile KEK session     */
//    0x1F, 0x07, ENCRYPT_NO,   /* Write host key V2 plaintext   */
//    0x1F, 0x08, ENCRYPT_NO,   /* Write host key V2 wrapped     */
//    0x1F, 0x09, ENCRYPT_NO,   /* Write symmetric key wrapped   */
//    0x1F, 0x0A, ENCRYPT_NO,   /* Write public key              */
//    0x1F, 0x0B, ENCRYPT_NO,   /* Generate ECDHE key            */
//    0x1F, 0x0C, ENCRYPT_NO,   /* --Reserved-- : Do not modify  */
//    0x1F, 0x0D, ENCRYPT_NO,   /* --Reserved-- : Do not modify  */
//    0x1F, 0x0E, ENCRYPT_NO,   /* Generate challenge            */
//    0x1F, 0x0F, ENCRYPT_NO,   /* Verify entity signature       */
//    0x1F, 0x10, ENCRYPT_NO,   /* Derive keys                   */
//    0x1F, 0x11, ENCRYPT_NO,   /* Start encrypt                 */
//    0x1F, 0x12, ENCRYPT_NO,   /* Process encrypt               */
//    0x1F, 0x13, ENCRYPT_NO,   /* Finish encrypt                */
//    0x1F, 0x14, ENCRYPT_NO,   /* Start decrypt                 */
//    0x1F, 0x15, ENCRYPT_NO,   /* Process decrypt               */
//    0x1F, 0x16, ENCRYPT_NO,   /* Finish decrypt                */
//    0x1F, 0x17, ENCRYPT_NO,   /* Write symmetric key plaintext */
//    0x1F, 0x18, ENCRYPT_NO,   /* Establish host key V2         */
//    0x1F, 0x19, ENCRYPT_NO,   /* Erase symmetric key slot      */
//    0x1F, 0x1A, ENCRYPT_NO,   /* Decompress public key         */
//};

/* STDIO redirect */
#if defined(__GNUC__) && !defined(__ARMCC_VERSION)
#define PUTCHAR_PROTOTYPE int __io_putchar(int ch)
#define GETCHAR_PROTOTYPE int __io_getchar()
#else
#define PUTCHAR_PROTOTYPE int fputc(int ch, FILE *f)
#define GETCHAR_PROTOTYPE int fgetc(FILE *f)
#endif /* __GNUC__ */
PUTCHAR_PROTOTYPE {
    uart_putc(ch);
    return ch;
}
GETCHAR_PROTOTYPE {
    return uart_getc();
}

void apps_print_command_ac_record_table(stse_cmd_authorization_record_t *command_ac_record_table,
                                        uint8_t total_command_count) {
    uint8_t i;

    printf("\n\r  HEADER | EXT-HEADER |    AC   | CMDEnc | RSPEnc  ");
    for (i = 0; i < total_command_count; i++) {
        printf("\n\r");
        /*- print HEADER (col 1)*/
        printf("   0x%02X  | ", command_ac_record_table[i].header);

        /*- print EXT-HEADER (col 2)*/
        if (command_ac_record_table[i].extended_header != 0) {
            printf("    0x%02X   | ", command_ac_record_table[i].extended_header);
        } else {
            printf("     -     | ");
        }

        /*- Access conditions (col 3) */
        switch (command_ac_record_table[i].command_AC) {
        case STSE_CMD_AC_NEVER:
            printf(" NEVER  |");
            break;
        case STSE_CMD_AC_FREE:
            printf("  FREE  |");
            break;
        case STSE_CMD_AC_ADMIN:
            printf(" ADMIN  |");
            break;
        case STSE_CMD_AC_HOST:
            printf("  HOST  |");
            break;
        case STSE_CMD_AC_ADMIN_OR_PWD:
            printf("ADM/PWD |");
            break;
        case STSE_CMD_AC_ADMIN_OR_HOST:
            printf(" ADM/HST |");
            break;
        default:
            printf("  --?--  |");
            break;
        }

        /*- cmd encryption (col 4) */
        printf(" %s | ", (command_ac_record_table[i].host_encryption_flags.cmd) == 1 ? "  YES " : "  NO  ");
        /*- rsp encryption (col 5) */
        printf(" %s | ", (command_ac_record_table[i].host_encryption_flags.rsp) == 1 ? "  YES " : "  NO  ");
    }
}

void apps_terminal_init(uint32_t baudrate) {
    (void)baudrate;
    /* - Initialize UART for example output log (baud 115200)  */
    uart_init(115200);
    /* Disable I/O buffering for STDOUT stream*/
    setvbuf(stdout, NULL, _IONBF, 0);
    /* - Clear terminal */
    printf(PRINT_RESET PRINT_CLEAR_SCREEN);
}

uint8_t apps_terminal_read_string(char *string, uint8_t *length) {
    char c = 1;
    uint16_t i = 0;
    while (c != '\r') {
        c = uart_getc();
        uart_putc(c);
        if (string != NULL) {
            string[i] = c;
        }
        i++;
        if (((length != NULL) && (i > *length)) || ((length == NULL) && (i > 0))) {
            return 1;
        }
    }
    if (length != NULL) {
        *length = i;
    }
    return 0;
}

uint8_t apps_terminal_read_unsigned_integer(uint16_t *integer) {
    uint8_t length = 6;
    char string[length];
    if (apps_terminal_read_string(string, &length)) {
        return 1;
    }

    *integer = (uint8_t)atoi(string);

    return 0;
}

uint32_t apps_generate_random_number(void) {
    return rng_generate_random_number();
}

void apps_randomize_buffer(uint8_t *pBuffer, uint16_t buffer_length) {
    for (uint16_t i = 0; i < buffer_length; i++) {
        *(pBuffer + i) = (rng_generate_random_number() & 0xFF);
    }
}

uint8_t apps_compare_buffers(uint8_t *pBuffer1, uint8_t *pBuffer2, uint16_t buffers_length) {

    for (uint16_t i = 0; i < buffers_length; i++) {
        if (*pBuffer1 != *pBuffer2) {
            return 1;
        }
    }

    return 0;
}

int main(void) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t stse_handler;
    static stse_perso_info_t stsafe_a120_spl05_perso_info = {.cmd_AC_status = 0x4151540450141511, .ext_cmd_AC_status = 0x15555555555554};
    PLAT_UI8 total_command_count = 0;
    stse_cmd_authorization_CR_t change_rights;
    PLAT_UI8 put_cmd_AC_header[] = {0x10};
    PLAT_UI8 put_cmd_AC_tags[] = {0x29, 0x2D};
    PLAT_UI8 put_cmd_enc_header[] = {0x10};
    PLAT_UI8 put_cmd_enc_tags[] = {0x2A, 0x2D};
    PLAT_UI8 rsp_header;

    /*- Create CMD / RSP frames */
    stse_frame_allocate(CmdFrame);
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, 1, NULL);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_tags, 2, NULL);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_payload, sizeof(command_AC_table), NULL);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);

    /* - Initialize Terminal */
    apps_terminal_init(115200);

    printf("\n\r ## STSAFE-A120 - Configure command access conditions & encryption ##");

    /* - Run all Test Suits */
    uart_getc();

    /* ## Initialize STSAFE-A1xx device handler */
    stse_ret = stse_set_default_handler_value(&stse_handler);
    if (stse_ret != STSE_OK) {
        printf("\n\r ## stse_set_default_handler_value ERROR : 0x%04X\n\r", stse_ret);
        while (1)
            ;
    }
    stse_handler.device_type = STSAFE_A120;
    stse_handler.io.Devaddr = 0x20;
    stse_handler.io.busID = 1;                                // Needed to use expansion board I2C
    stse_handler.pPerso_info = &stsafe_a120_spl05_perso_info; // Use STSAFE-A120 SPL05 static personalization information

    printf("\n\r - Initialize target STSAFE-A120");
    stse_ret = stse_init(&stse_handler);
    if (stse_ret != STSE_OK) {
        printf("\n\r ## stse_init ERROR : 0x%04X\n\r", stse_ret);
        while (1)
            ;
    }

    stse_ret = stsafea_get_command_count(&stse_handler, &total_command_count);
    if (stse_ret != STSE_OK) {
        printf("\n\n\r - query command AC error: 0x%04X", stse_ret);
    }

    stse_cmd_authorization_record_t record_table[total_command_count];
    stse_ret = stsafea_get_command_AC_table(&stse_handler,
                                            total_command_count,
                                            &change_rights,
                                            record_table);
    if (stse_ret != STSE_OK) {
        printf("\n\n\r - query command AC error: 0x%04X", stse_ret);
    }

    printf("\n\n\r - Current STSAFE-A120 Command AC table (AC CR=%d / Enc CR=%d)\n", change_rights.cmd_AC_CR, change_rights.host_encryption_flag_CR);
    apps_print_command_ac_record_table(record_table, total_command_count);

    /*- Put command AC conditions */
    eCmd_header.pData = put_cmd_AC_header;
    eCmd_tags.pData = put_cmd_AC_tags;
    eCmd_payload.pData = command_AC_table;
    stse_ret = stsafea_frame_transfer(&stse_handler,
                                      &CmdFrame,
                                      &RspFrame);
    if (stse_ret != STSE_OK) {
        printf("\n\n\r - put command AC error: 0x%04X", stse_ret);
    } else if (rsp_header != STSE_OK) {
        printf("\n\n\r - put command AC error: 0x%04X", rsp_header);
    } else {
        printf("\n\n\r - STSAFE-A120 Commands AC updated ");
    }

    /*- Put command encryption */
    eCmd_header.pData = put_cmd_enc_header;
    eCmd_tags.pData = put_cmd_enc_tags;
    eCmd_payload.pData = command_encryption_table;
    stse_ret = stsafea_frame_transfer(&stse_handler,
                                      &CmdFrame,
                                      &RspFrame);
    if (stse_ret != STSE_OK) {
        printf("\n\n\r - put command encryption error: 0x%04X", stse_ret);
    } else if (rsp_header != STSE_OK) {
        printf("\n\n\r - put command encryption error: 0x%04X", rsp_header);
    } else {
        printf("\n\n\r - STSAFE-A120 Commands encryption updated ");
    }

    stse_ret = stsafea_get_command_AC_table(&stse_handler,
                                            total_command_count,
                                            &change_rights,
                                            record_table);
    if (stse_ret != STSE_OK) {
        printf("\n\n\r - query command AC error: 0x%04X", stse_ret);
        while (1)
            ;
    }

    printf("\n\n\r - Updated STSAFE-A120 Command AC table (AC CR=%d / Enc CR=%d)\n", change_rights.cmd_AC_CR, change_rights.host_encryption_flag_CR);
    apps_print_command_ac_record_table(record_table, total_command_count);

    /* - Display key table provisioning control fields information in serial terminal */
    printf("\n\n\r");

    /* Configure symmetric key slot to enable the write key command */
    stsafea_symmetric_key_slot_provisioning_ctrl_fields_t ctrl_fields = {0};
    ctrl_fields.change_right = 0;
    ctrl_fields.derived = 1;
    ctrl_fields.plaintext = 1;
    ctrl_fields.wrapped_anonymous = 1;
    ctrl_fields.ECDHE_anonymous = 1;
    ctrl_fields.wrapped_authentication_key = 0xFF;
    ctrl_fields.ECDHE_authentication_key = 0xFF;

    for (uint8_t i = 0; i < 15; i++) {

        /* - Write selected symmetric key slot provisioning control fields */
        stse_ret = stsafea_put_symmetric_key_slot_provisioning_ctrl_fields(
            &stse_handler,
            (PLAT_UI8)i,
            &ctrl_fields);
        printf("\n\n\r - Put slot %u provisioning ctrl fields : ", i);
        if (stse_ret == STSE_OK) {
            printf("OK");
        } else if (stse_ret == STSE_ACCESS_CONDITION_NOT_SATISFIED) {
            printf("Already done");
        } else {
            printf("Error 0x%04X", stse_ret);
        }
    }

    while (1) {
        /* - Infinite loop */
    }
}

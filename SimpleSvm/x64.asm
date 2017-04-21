;
; @file       x64.asm
;
; @brief      TBD.
;
; @author     Satoshi Tanda
;
; @copyright  Copyright (c) 2017, Satoshi Tanda. All rights reserved.
;
.code

extern SvHandleVmExit : proc

;
;   @brief      Saves all general purpose registers to the stack.
;
;   @details    This macro does not alter the flag register.
;
PUSHAQ macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1      ; dummy for rsp
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

;
;   @brief      Loads all general purpose registers from the stack.
;
;   @details    This macro does not alter the flag register.
;
POPAQ macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx    ; dummy for rsp (this value is destroyed by the next pop)
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

;
;   @brief      TBD.
;
;   @details    TBD.
;
;   @param[in]  HostRsp - A stack pointer for the hypervisor.
;
SvLaunchVm proc
        ;
        ; Update the current stack pointer with the host RSP. This avoids values
        ; stored on stack for the hypervisor being overwritten by a guest due to
        ; using the same stack memory.
        ;
        mov rsp, rcx    ; Rsp <= HostRsp

SVLV10: mov rax, [rsp]  ; RAX <= GuestVmcbPa
        vmload rax      ; GuestVmcbPa
        vmrun rax       ; GuestVmcbPa

        ;
        ; GIF == 0
        ;
        vmsave rax      ; GuestVmcbPa

        PUSHAQ                      ; -8 * 16

        mov rdx, rsp                ; GuestRegisters
        mov rcx, [rsp + 8 * 18]     ; VpData (18 = 16 + GuestVmcbPa + HostVmcbPa)
        sub rsp, 20h
        call SvHandleVmExit
        add rsp, 20h

        test al, al
        POPAQ
        jnz SVLV20                  ; if (ExitVm != 0) jmp SVLV20
        jmp SVLV10                  ;

SVLV20: mov rsp, rax
        mov eax, 'SSVM'
        push rbx
        ret
SvLaunchVm endp

        end

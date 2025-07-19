#pragma once
#include <stdint.h>
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#include <driver/xorstr.h>
#include <core/ia32.h>

// this won't output anything anymore.

#define printf(text, ...) //DbgPrintEx(DPFLTR_IHVBUS_ID, 0, XORS("[WKD]: " text), ##__VA_ARGS__)

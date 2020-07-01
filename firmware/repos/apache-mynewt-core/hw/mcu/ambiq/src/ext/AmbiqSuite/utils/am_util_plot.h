//*****************************************************************************
//
//! @file am_util_plot.h
//!
//! @brief A few useful plot functions to be used with AM Flash.
//
//*****************************************************************************

//*****************************************************************************
//
// Copyright (c) 2017, Ambiq Micro
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// This is part of revision v1.2.10-2-gea660ad-hotfix2 of the AmbiqSuite Development Package.
//
//*****************************************************************************
#ifndef AM_UTIL_PLOT_H
#define AM_UTIL_PLOT_H

#ifdef __cplusplus
extern "C"
{
#endif

//*****************************************************************************
//
//! @name Trace defines
//! @brief Trace defines for valid plot traces
//!
//! These macros should be used to specify which trace to update for plotting.
//! @{
//
//*****************************************************************************
#define AM_UTIL_PLOT_0              24
#define AM_UTIL_PLOT_1              25
#define AM_UTIL_PLOT_2              26
#define AM_UTIL_PLOT_3              27
//! @}

//
// Define for the frequency of sync packets.
//
#define AM_UTIL_PLOT_SYNC_SEND      64

//*****************************************************************************
//
// External function definitions
//
//*****************************************************************************
extern void am_util_plot_init(void);
extern void am_util_plot_int(uint32_t ui32Trace, int32_t i32Value);
extern void am_util_plot_byte(uint32_t ui32Trace, uint8_t ui8Value);


#ifdef __cplusplus
}
#endif

#endif // AM_UTIL_PLOT_H


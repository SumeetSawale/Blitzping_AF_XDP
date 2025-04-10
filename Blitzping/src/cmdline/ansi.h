// ---------------------------------------------------------------------
// SPDX-License-Identifier: GPL-3.0-or-later
// ansi.h is a part of Blitzping.
// ---------------------------------------------------------------------

_Pragma ("once")
#ifndef ANSI_H
#define ANSI_H

#include <stdbool.h>

// Compile-time flag to enable/disable ANSI formatting
// (If enabled, formatting can still be disabled at runtime.)
#ifndef DISABLE_ANSI_FORMATTING
#    define ANSI_ENABLED 1
#else
#    define ANSI_ENABLED 0
#endif

// "The name ANSI is misleading; ANSI [which was formerly known as the
// "American Standards Association" (ASA)] simply stands for "American
// National Standards Institute," a non-profit body that was founded in
// 1918, which was meant to be a place where American industries could
// agree on standards which would then be used by all companies without
// variation.  The theory was (and is) that by having all these
// disparate groups agree on, say, the size of a washer, or the width
// of a rail, then there's less infighting over forcing the customer
// base/world to have to choose a specific company's standard, and the
// focus is on making the American industry as a whole the dominant
// factor in domestic and foreign markets.
//     There is a graphics standard in DOS on IBM Computers called
// "ANSI" (which is actually ANSI standard X3.64-1979 or ISO standard
// DP-6429 and ECMA-35) which was implemented in the early 1980s.  It
// allowed a certain set of escape sequences to be included in files
// that would produce color and cursor movement on the screen, and was
// used to great benefit on DOS machines for some time, especially some
// BBS menus and welcome screens.  Towards the early 1990's, an entire
// "ANSI scene" rose up where people tried to outdo each other producing
// elaborate ANSI images or files."
//
// (http://artscene.textfiles.com/ansi)
//
// Rooted in the English Alphabet's telegraph code of the 19th century,
// the ASCII character encoding standard was developed by the American
// Standards Association's (ASA, now known as ANSI) X3.2 subcommittee
// (later known as the X3L2 committee) and first published in 1963 as
// ASA X3.4-1963.  ASCII underwent several revisions as USAS X3.4-1967,
// USAS X3.4-1968, ANSI X3.4-1977, and finally ANSI X3.4-1986.  Other
// committees, in standards like X3.15, further addressed how ASCII
// should be transmitted and recorded on tape.
//     ASCII had various characters reserved as "control characters,"
// such as XOFF (transmit off) to cause a connected tape reader to stop
// as a part of communication flow control.  There were various other
// shortcomings and workarounds (e.g., delete vs. backspace) for use
// with physical typewriters and teletype printers, too.
//     This brings us to the "Escape" character (ASCII 27), which was
// originally meant to allow sending the aforementioned control codes as
// literals instead of invoking their meaning, an "escape sequence."
// Nowadays, in modern context, ESC sent to the terminal indicates the
// start of a command sequence, such as moving the cursor, changing text
// attributes, clearing the screen, etc.
//
// (https://en.wikipedia.org/wiki/ASCII)
//
// "Almost all manufacturers of video terminals added vendor-specific
// escape sequences to perform operations such as placing the cursor at
// arbitrary positions on the screen.  One example is the VT52 terminal,
// which allowed the cursor to be placed at an x,y location on the
// screen by sending the ESC character, a Y character, and then two
// characters representing numerical values equal to the x,y location
// plus 32 (thus starting at the ASCII space character and avoiding
// the control characters).  The Hazeltine 1500 had a similar feature, 
// invoked using !, DC1 and then the X and Y positions separated with a
// comma. While the two terminals had identical functionality in this
// regard, different control sequences had to be used to invoke them.
//     As these sequences were different for different terminals,
// elaborate libraries such as termcap ("terminal capabilities") and
// utilities such as tput had to be created so programs could use the
// same API to work with any terminal.  In addition, many of these
// terminals required sending numbers (such as row and column) as the
// binary values of the characters; for some programming languages, and
// for systems that did not use ASCII internally, it was often difficult
// to turn a number into the correct character.
//     The ANSI standard attempted to address these problems by making a
// command set that all terminals would use and requiring all numeric
// information to be transmitted as ASCII numbers.  The first standard
// in the series was ECMA-48, adopted in 1976.  It was a continuation of
// a series of character coding standards, the first one being ECMA-6
// from 1965, a 7-bit standard from which ISO 646 originates.  The name
// "ANSI escape sequence" dates from 1979 when ANSI adopted ANSI X3.64.
// The ANSI X3L2 committee collaborated with the ECMA committee TC 1 to
// produce nearly identical standards.  These two standards were merged
// into an international standard, ISO 6429.  In 1994, ANSI withdrew its
// standard in favor of the international standard.
//     The first popular video terminal to support these sequences was
// the Digital VT100, introduced in 1978. This model was very successful
// in the market, which sparked a variety of VT100 clones, among the
// earliest and most popular of which was the much more affordable
// Zenith Z-19 in 1979.  Others included the Qume QVT-108, Televideo
// TVI-970, Wyse WY-99GT as well as optional "VT100" or "VT103" or
// "ANSI" modes with varying degrees of compatibility on many other
// brands.  The popularity of these gradually led to more and more
// software (especially bulletin board systems [BBS] and other online
// services) assuming the escape sequences worked, leading to almost
// all new terminals and emulator programs supporting them.
//     In 1981, ANSI X3.64 was adopted for use in the U.S. government by
// FIPS [Federal Information Processing Standards] publication 86.
// Later, the U.S. government stopped duplicating industry standards,
// so FIPS pub. 86 was withdrawn.
//     ECMA-48 has been updated several times and is currently [as 2025]
// at its 5th edition, from 1991.  It is also adopted by ISO and IEC
// as standard ISO/IEC 6429. A version is adopted as a Japanese
// Industrial Standard, as JIS X 0211.
//     Related standards include [United Nation's International
// Telecommunication Union's] ITU T.61, the Teletex standard, and
// the ISO/IEC 8613, the Open Document Architecture standard (mainly
// ISO/IEC 8613-6 or ITU T.416).  The two systems share many escape
// codes with the ANSI system, with extensions that are not necessarily
// meaningful to computer terminals.  Both systems quickly fell into
// disuse, but ECMA-48 marks the extensions used in them as reserved."
//
// (https://en.wikipedia.org/wiki/ANSI_escape_code)
//
// Standards (most were withdrawn in favor of ISO/IEC 6429):
//   ANSI X3.4-1986
//   U.N. ITU T.61
//   U.S. FIPS Publication 86
//   ISO/IEC DP-6429
//   JIS X 0211
//   ECMA-48

// NOTE: Even though ANSI support would remain optional (configurable at
// both compile-time and runtime), do still try to use only the bare-
// minimum feature set of ANSI that is supported almost anywhere; many
// of its features (e.g., italic, true-color, strikethrough, etc.)
// are not supported universally among all terminal emulators.
//     As a general guideline, strive for compatibility with Linux TTY
// (TeleTYpewriter) terminals.  While it's true that most Linux systems
// will have xterm or more advanced terminals, Windows 10/11+ will have
// Windows Terminal, and that macOS will have Terminal.app, TTYs remain
// the most portable, non-GUI way by default.
//     POSIX standardizes basic terminal I/O interfaces (tcgetattr,
// tcsetattr, etc.) but the exact feature set, especially color support,
// varies across systems.  The TTY standard primarily defines the basic
// input/output behaviors like cooked/raw modes and signal handling (^C,
// ^Z) but does not mandate support for specific ANSI escape sequences
// or color capabilities.
//     When writing cross-platform software using ANSI colors, you
// generally have two options: (1) Use only the most basic 3-bit/8-color
// subset that works almost everywhere, or (2) Use terminfo/termcap/
// ncurses to detect the terminal's actual capabilities at runtime.
//     When you see "VT100," "VT102," "xterm," or "linux" in your $TERM
// variable, that indicates the emulation your terminal is claiming.
// This tells programs (and libraries like ncurses) what control
// sequences they can (probably) use.  A "real TTY" on a physical
// console (e.g., /dev/tty1 on Linux) often emulates a subset of VT102
// (plus Linux-specific extras).
//     An "SSH TTY" (actually a pseudo-terminal, /dev/pts/...) might
// advertise itself as xterm-256color or something else.
//
// https://en.wikipedia.org/wiki/List_of_terminal_emulators
//
// Jargon and Terminology:
//   Console
//     Physical display and keyboard directly connected to a computer.
//   Shell
//     Command-line interpreter that reads text commands from the user
//     and returns some result (e.g., bash, zsh, cmd.exe, PowerShell).
//   Terminal
//     Teletypes/video terminals that provided remote computer access.
//   Terminal Emulator
//     Software that emulates a hardware terminal (e.g., xterm, rxvt).
//     https://en.wikipedia.org/wiki/List_of_terminal_emulators
//   Virtual Terminal (VT)
//     Multiple terminal sessions you can switch between (tty1-tty6)
//     (Note that the VT in VT100 stood for "Video Terminal.")
//   Pseudo-terminal (PTY)
//     Using a terminal emulator to connect to a remote host (e.g., SSH)
//     https://en.wikipedia.org/wiki/Pseudoterminal
//   VGA Text Attributes
//     https://en.wikipedia.org/wiki/VGA_text_mode
//     https://wiki.osdev.org/Text_UI


// Consult these resources for the bare-minimum ANSI escape sequences:
//   https://www.man7.org/linux/man-pages/man4/console_codes.4.html
//   https://vt100.net/docs/vt102-ug/contents.html
//   https://tldp.org/HOWTO/Text-Terminal-HOWTO-10.html


// Initialize ANSI settings
void ansi_init();

// TODO: Make the compile-time macro also make these unreachable as to
// avoid having them compiled into the code when they shouldn't be.
// Enable ANSI formatting at runtime
void ansi_enable();
// Disable ANSI formatting at runtime
void ansi_disable();


// "In order to tell the terminal we want to use an escape sequence,
// and not print out a piece of text verbatim, we have a special escape
// character, in unix-like systems the escape character is usually \e or
// \033, after which another character follows, usually terminated by a
// BEL (\007) or ST (Usually ESC).  A lot of escape sequences are
// terminated using various other characters.
//
// https://medium.com/israeli-tech-radar/
//     terminal-escape-codes-are-awesome-heres-why-c8eb938b1a1c
//
// "A character is a control character if (before transformation
// according to the mapping table) it has one of the 14 codes 00 (NUL),
// 07 (BEL), 08 (BS), 09 (HT), 0a (LF), 0b (VT), 0c (FF), 0d (CR),
// 0e (SO), 0f (SI), 18 (CAN), 1a (SUB), 1b (ESC), 7f (DEL).
// One can set a "display control characters" mode (see below), and
// allow 07, 09, 0b, 18, 1a, 7f to be displayed as glyphs.  On the
// other hand, in UTF-8 mode all codes 00–1f are regarded as control
// characters, regardless of any "display control characters" mode."
//     If we have a control character, it is acted upon immediately and
// then discarded (even in the middle of an escape sequence) and the
// escape sequence continues with the next character.  (However, ESC
// starts a new escape sequence, possibly aborting a previous unfinished
// one, and CAN and SUB abort any escape sequence.)  The recognized
// control characters are BEL, BS, HT, LF, VT, FF, CR, SO, SI, CAN, SUB,
// ESC, DEL, CSI."
//
// NOTE: "\e" is a non-standard escape code for the ASCII ESC character;
// it works in GCC/LLVM/TCC but isn't standard C.  (Use "\x1b")
// Standard escape codes are prefixed with Escape:
//     Caret/Ctrl-Key : ^[
//     Octal          : \033
//     Unicode        : \u001b
//     Hexadecimal    : \x1b
//     Decimal        : 27
#define ANSI_ESC(code) "\x1b[" #code "m"

#define ESC "\x1b"
#define CSI "\x1b["


// NOTE: 3-bit colors (i.e., 8 colors) are the most widely supported.
// You might have heard about "16 colors," but that is a misnomer; in
// reality, they are combining the "bold" attribute with the 8 colors,
// making the existing 3-bit colors more intense.  (Not to mention that
// the "bold" attribute affects only foreground colors, not background.)
//     Nowadays, most terminals support 256 colors and even true-color
// (i.e., 24-bit RGB), but we'll stick to basic attributes and 3-bit.
// Get ANSI escape sequence based on current settings


const char *ansi_get_reset();
const char *ansi_get_red();
const char *ansi_get_green();
const char *ansi_get_yellow();
const char *ansi_get_blue();
const char *ansi_get_bold();

//Reset
#define reset "\e[0m"
#define CRESET "\e[0m"
#define COLOR_RESET "\e[0m"

// Macro to generate ANSI color codes
#define COLOR(code) "\x1b[" #code "m"

// Predefined color codes using the macro
#define RED     COLOR(31)
#define GREEN   COLOR(32)
#define YELLOW  COLOR(33)
#define BLUE    COLOR(34)
#define MAGENTA COLOR(35)
#define CYAN    COLOR(36)
#define RESET   COLOR(0)


// Struct to group ANSI color strings
typedef struct ansi_color_codes {
    const char* RESET;
    const char* RED;
    const char* GREEN;
    const char* YELLOW;
    const char* BLUE;
    const char* MAGENTA;
    const char* CYAN;
    // Add more color strings as needed
} ansi_color_codes_t;

// Initialize ANSI color codes
static const ansi_color_codes_t ANSI_COLORS = {
    .RESET   = "\x1b[0m",
    .RED     = "\x1b[31m",
    .GREEN   = "\x1b[32m",
    .YELLOW  = "\x1b[33m",
    .BLUE    = "\x1b[34m",
    .MAGENTA = "\x1b[35m",
    .CYAN    = "\x1b[36m",
    // Initialize more colors as needed
};


#if defined(_POSIX_C_SOURCE)
bool enable_vt_mode() {
    // No need to enable manually ANSI colors on POSIX systems
    return true;
}
#elif defined(_WIN32)
// Newer Windows 10 and 11 versions support ANSI colors in the console
// and Windows Terminal, but they have to be enabled manually:
// https://learn.microsoft.com/en-us/windows/console/
//     console-virtual-terminal-sequences
//
// TODO: Older console versions do have formatting, but it's not ANSI.
bool enable_vt_mode() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) {
        return false;
    }

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hOut, dwMode)) {
        return false;
    }

    return true;
}
#endif



#endif // ANSI_H

// ---------------------------------------------------------------------
// END OF FILE: ansi.h
// ---------------------------------------------------------------------

#!/bin/bash
set -e

echo "[*] Generating comprehensive seed corpus..."

mkdir -p fuzz_input/corpus

# Basic escape sequences
echo -ne '\x1b[H' > fuzz_input/corpus/seed_home.bin
echo -ne '\x1b[2J' > fuzz_input/corpus/seed_clear.bin
echo -ne '\x1b[?1000h' > fuzz_input/corpus/seed_mouse_on.bin
echo -ne '\x1b[?1000l' > fuzz_input/corpus/seed_mouse_off.bin
echo -ne '\x1b[?2004h' > fuzz_input/corpus/seed_bracketed_paste_on.bin
echo -ne '\x1b[?2004l' > fuzz_input/corpus/seed_bracketed_paste_off.bin

# Colors and attributes
echo -ne '\x1b[0m' > fuzz_input/corpus/seed_reset.bin
echo -ne '\x1b[1m' > fuzz_input/corpus/seed_bold.bin
echo -ne '\x1b[4m' > fuzz_input/corpus/seed_underline.bin
echo -ne '\x1b[7m' > fuzz_input/corpus/seed_reverse.bin
echo -ne '\x1b[31m' > fuzz_input/corpus/seed_red.bin
echo -ne '\x1b[32m' > fuzz_input/corpus/seed_green.bin
echo -ne '\x1b[38;2;255;0;0m' > fuzz_input/corpus/seed_rgb.bin
echo -ne '\x1b[48;5;123m' > fuzz_input/corpus/seed_256color.bin

# Cursor movement
echo -ne '\x1b[10;20H' > fuzz_input/corpus/seed_cursor_pos.bin
echo -ne '\x1b[A' > fuzz_input/corpus/seed_cursor_up.bin
echo -ne '\x1b[B' > fuzz_input/corpus/seed_cursor_down.bin
echo -ne '\x1b[C' > fuzz_input/corpus/seed_cursor_right.bin
echo -ne '\x1b[D' > fuzz_input/corpus/seed_cursor_left.bin

# Screen manipulation
echo -ne '\x1b[?1049h' > fuzz_input/corpus/seed_alt_screen_on.bin
echo -ne '\x1b[?1049l' > fuzz_input/corpus/seed_alt_screen_off.bin
echo -ne '\x1b[3J' > fuzz_input/corpus/seed_clear_scrollback.bin

# OSC sequences (Operating System Command)
echo -ne '\x1b]0;Title\x07' > fuzz_input/corpus/seed_title.bin
echo -ne '\x1b]52;c;SGVsbG8=\x07' > fuzz_input/corpus/seed_clipboard.bin
echo -ne '\x1b]10;rgb:ff/00/00\x07' > fuzz_input/corpus/seed_fg_color.bin
echo -ne '\x1b]11;rgb:00/00/ff\x07' > fuzz_input/corpus/seed_bg_color.bin

# DCS sequences (Device Control String)
echo -ne '\x1bP$q m\x1b\\' > fuzz_input/corpus/seed_dcs_query.bin

# Complex sequences
echo -ne '\x1b[1;31;44mRED ON BLUE\x1b[0m' > fuzz_input/corpus/seed_complex_color.bin
echo -ne '\x1b[?1000h\x1b[?1002h\x1b[?1006h' > fuzz_input/corpus/seed_mouse_complex.bin

# Text with attributes
echo -ne 'Hello\x1b[1mBold\x1b[0mWorld' > fuzz_input/corpus/seed_mixed_text.bin

# Long sequences
printf '\x1b[' > fuzz_input/corpus/seed_long_csi.bin
for i in {1..50}; do printf '1;' >> fuzz_input/corpus/seed_long_csi.bin; done
printf 'm' >> fuzz_input/corpus/seed_long_csi.bin

# Edge cases
echo -ne '\x1b' > fuzz_input/corpus/seed_incomplete_esc.bin
echo -ne '\x1b[' > fuzz_input/corpus/seed_incomplete_csi.bin
echo -ne '\x1b[999999999;999999999H' > fuzz_input/corpus/seed_huge_nums.bin
echo -ne '\x1b[0;0;0;0;0;0;0;0;0m' > fuzz_input/corpus/seed_many_params.bin

# UTF-8 sequences
echo -ne 'Hello 世界 🚀' > fuzz_input/corpus/seed_utf8.bin
echo -ne '\x1b[1m世界\x1b[0m' > fuzz_input/corpus/seed_utf8_colored.bin

# Sixel graphics (if supported)
echo -ne '\x1bPq"1;1;100;100\x1b\\' > fuzz_input/corpus/seed_sixel.bin

echo "[*] Generated $(ls fuzz_input/corpus/ | wc -l) seed files"
ls -lh fuzz_input/corpus/

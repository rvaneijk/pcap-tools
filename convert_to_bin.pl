#!/usr/bin/perl
#
# convert octal to bin, which can easily be viewed in the VI editor
#
# Copyright 2010, Rob van Eijk <rob@blaeu.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# Usage:
#
# converter-to-bin.pl <file>
# converter-to-bin.pl <file1> <file2> ...
# converter-to-bin.pl <*.log>
#
# When viewing the converted_file.pcap in vim, use the following command to switch to view hex with ASCII
#  <Esc>:%!xxd
# The command for switching back to binary is:
#  <Esc>:%!xdd -r

use strict;

my ($argtot, $outputfile, $argnum, $line, $line_length, $portion, $chars, $charlen, $tmpval, $numfiles, $cnt);
my (@chars);

$argtot=$#ARGV;		# i.e. "*.log"
$numfiles=$argtot +1;

die "Could not create output file 'converted_file' to write to" if (!open($outputfile,">converted_file.bin")); 

# MAIN
#
foreach my $argnum (0 .. $argtot)
{
    if (open(INPUTFILE,$ARGV[$argnum])) {

	$tmpval = $argnum +1;
	  print STDERR "Converting...\n";
	  print STDERR "[$tmpval of $numfiles] $ARGV[$argnum]\n";
	  while ($line = <INPUTFILE>) {				# line by line
		chomp $line;
		exit unless defined $line;
		$line_length = length ($line);
		$portion = substr($line, 2 , 4);
		if ($portion eq "Raw:") {				# processing RAW data
			$portion = substr($line,8,$line_length-9);
			@chars = split /\\/, $portion;
			$cnt = 1;
			$chars = @chars;
			while ($cnt < $chars){
				$charlen = 0;
				$charlen = length ($chars[$cnt]);
				if ($charlen > 3) {
						if ($chars[$cnt] =~ /[0-7]/) {
                           	printf $outputfile chr( oct(substr($chars[$cnt],0,3)) );	# oct, convert to hex
						} else {	
                           	printf $outputfile substr($chars[$cnt],0,3); 				# no oct, leave alfanumeric
						}
						printf $outputfile substr($chars[$cnt],3,$charlen-3);			# leave the rest alfanumeric
				} else {
				if ($charlen < 3) {
						printf $outputfile $chars[$cnt];								# alfanumeric only
				} else {
				if ($charlen == 3) {
						if ($chars[$cnt] =~ /[0-7]/) {
                           	printf $outputfile chr( oct($chars[$cnt]) ); 				# oct, convert to hex
						} else {	
                           	printf $outputfile $chars[$cnt]; 							# no oct, leave alfanumeric
							}
						}
					}
				}
			$cnt++;
			}
		} # end RAW
	  } # end line by line
	close(INPUTFILE);
	}
} # end for each

print STDERR "Done.\n\n";
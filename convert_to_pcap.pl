#!/usr/bin/perl
#
# convert octal to hex, in order to create pcap file
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
# converter-to-pcap.pl <file>
# converter-to-pcap.pl <file1> <file2>
# converter-to-pcap.pl <*.log>
#
# Run TEXT2PCAP manually to convert this hex-file to common
# PCAP format for further analysis (eg. CAPINFOS)
#
# text2pcap converted_file.pcap <outfile>.pcap
# capinfos <outfile>.pcap

use strict;

my ($argtot, $outputfile, $argnum, $line, $line_length, $portion, $sub, $linenumber);
my ($chars, $cnt, $charlen, $cntcharlen, $tmpval,$numfiles, $offset, $chkint, $tmploop, $elements);
my ($readlines, $readraw, $writtenlines);
my (@chars, @myhexval);

$argtot=$#ARGV;		# i.e. "*.log"
$numfiles=$argtot +1;
$readlines=0;
$writtenlines=0;
$readraw=0;
	
die "Could not create output file 'converted_file' to write to" if (!open($outputfile,">converted_file.pcap")); 

# MAIN
#
foreach my $argnum (0 .. $argtot)
{
    if (open(INPUTFILE,$ARGV[$argnum])) {

	$tmpval = $argnum +1;
	  print STDERR "Converting...\n";
	  print STDERR "[$tmpval of $numfiles] $ARGV[$argnum]\n";
	$linenumber = 0;

	  while ($line = <INPUTFILE>) {				# line by line
		chomp $line;
		exit unless defined $line;
		$readlines++;
		$offset = 0;
		$line_length = length ($line);
		$portion = substr($line, 2 , 4);
		if ($portion eq "Raw:") {				# processing RAW data
			$readraw++;
			$portion = substr($line,8,$line_length-9);
			@chars = split /\\/, $portion;
			$cnt = 1;
			$chars = @chars;

			my @lineout;
			$offset++;

			while ($cnt < $chars){
				$charlen = 0;
				$charlen = length ($chars[$cnt]);
				if ($charlen > 3) {
								if ($chars[$cnt] =~ /[0-7]/) {
									$lineout[$offset] = oct(substr($chars[$cnt],0,3));
									$offset++;
								} else {	
									@myhexval = split //, substr($chars[$cnt],0,3);				# alfanumeric, convert to hex
									$lineout[$offset] = ord($myhexval[0]);
									$offset++;
									$lineout[$offset] = ord($myhexval[1]);
									$offset++;
									$lineout[$offset] = ord($myhexval[2]);
									$offset++;
									}

									@myhexval = split //, substr($chars[$cnt],3,$charlen-3);	# rest alfanumeric, convert to hex
									for ($tmploop=0; $tmploop<= $#myhexval; $tmploop++) { 
										$lineout[$offset] = ord($myhexval[$tmploop]);
										$offset++;
									}
				} else {
				if ($charlen < 3) {
									if ($charlen == 1) {
										$lineout[$offset] = $chars[$cnt];
										$offset++;
										} else {
										@myhexval = split //, $chars[$cnt];						# alfanumeric, convert to hex
										$lineout[$offset] = ord($myhexval[0]);
										$offset++;
										$lineout[$offset] = ord($myhexval[1]);
										$offset++;
									}
				} else {
				if ($charlen == 3) {
								if ($chars[$cnt] =~ /[0-7]/) {
                                	$lineout[$offset] = oct($chars[$cnt]);						# oct, convert to hex
									$offset++;
								} else {	
									@myhexval = split //, $chars[$cnt];							# alfanumeric, convert to hex
									$lineout[$offset] = ord($myhexval[0]);
									$offset++;
									$lineout[$offset] = ord($myhexval[1]);
									$offset++;
									$lineout[$offset] = ord($myhexval[2]);
									$offset++;
								}
						}
					}
				}
				$cnt++;
			}
		
			$elements = @lineout;

			printf $outputfile "%07x  ", $linenumber;
			$linenumber = $linenumber + 16;
			$writtenlines++;

			for ($tmploop=1; $tmploop <= $elements; $tmploop++) {
				
				printf $outputfile "%02x ", $lineout[$tmploop]; 								# write out hex values
				
				if ( $tmploop % 16 == 0 ) {
					printf $outputfile "\n";
					printf $outputfile "%07x  ", $linenumber; 			
					$linenumber = $linenumber + 16;
				}
			}
			printf $outputfile "\n";
			$linenumber = 0;
			undef (@lineout);
		} # end RAW 
	  } # end line by line
	close(INPUTFILE);
	}
} # end for each

printf "Done.\n\nFiles processed succesfully: $numfiles.\nNumber of lines processed: %d\nRaw packets read: %d, written: %d.\n", $readlines, $readraw, $writtenlines;
printf "\nRun TEXT2PCAP to convert this hex-file to common\nPCAP format for further analysis (eg. CAPINFOS, SNORT, TSHARK, TCPDUMP etc.)";

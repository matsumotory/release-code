#!/usr/bin/perl
#############################################################################################
#
# package
#
#############################################################################################
package Zabbix::API::Client::File;

use JSON;
use Encode;
use Encode::Guess qw/shift-jis euc-jp 7bit-jis/;

our $VERSION = 0.01;

sub json_from_file {

    my ($self, $file) = @_;

    open my $fh, '<', $file or die "Can't open file \"$file\": $!";
    my $content = do { local $/; <$fh> };
    close $fh;

    Encode::from_to($content, 'Guess', 'utf-8');

    return decode_json($content);
}


sub json_into_file {

    my ($self, $file, $json_hash) = @_;

    my $json_data = encode_json($json_hash);

    $self->file_write($file, "w", $json_data);

}

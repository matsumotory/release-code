#!/usr/bin/perl
#############################################################################################
#
#   Executed JSON Data for Zabbix API
#       Copyright (C) 2012 MATSUMOTO, Ryosuke
#
#
#   Usage:
#       /usr/local/sbin/zabbix-api-client.pl
#
#############################################################################################
#
# Change Log
#
# 2012/04/02 matsumoto_r first release
#
#############################################################################################

use strict;
use warnings;
use lib "/usr/local/lib/myperl_lib";
use Zabbix::API::Client;
use Data::Dump qw(dump);
use File::Spec;
use File::Basename;
use Getopt::Long;

our $VERSION    = '0.01';
our $SCRIPT     = basename($0);

my ($json_file, $method);

GetOptions(

    "--json-file|j=s"   =>  \$json_file,
    "--method|m=s"      =>  \$method,
    "--help"            =>  \&help,
    "--version"         =>  \&version,
);

my $METHOD_MAP = {
    
    view    =>  \&view,
    request =>  \&request,

};

my $API = Zabbix::API::Client->new(

    url             =>  "http://example.com/zabbix/api_jsonrpc.php",
    user_agent      =>  "Zabbix-API-Client",
    user            =>  "api-admin",
    pass            =>  "hogefuga",
    debug           =>  0,
    info            =>  0,
    warn            =>  0,
    error           =>  1,
    irc_owner       =>  $SCRIPT,
    tool_name       =>  $SCRIPT,
    log_file        =>  "/tmp/$SCRIPT.log",
    pid_file        =>  "/tmp/$SCRIPT.pid",
    lock_file       =>  "/tmp/$SCRIPT.lock",
    syslog_type     =>  $SCRIPT,

);

$SIG{INT}  = sub { $API->TASK_SIGINT };
$SIG{TERM} = sub { $API->TASK_SIGTERM };

$API->set_lock;
$API->make_pid_file;

&help if !defined $method;
&help if !defined $json_file;
&help if !exists $METHOD_MAP->{$method};

our $json_data = $API->json_from_file($json_file);

$METHOD_MAP->{$method}->($json_data);

exit 0;

sub view {

    my $json_data = shift;

    print dump($json_data) . "\n";
}

sub request {

    my $json_data = shift;

    my $response = $API->api_operation(
                                        $json_data->{method}, 
                                        $json_data->{object}, 
                                        $json_data->{params}
                                      );

    print dump($response) . "\n";
}

sub help {
    print <<USAGE;

    usage: ./$SCRIPT --json-file|-j JSON.FILE --method|-m view|request

USAGE
    exit(1);
}

sub version {

    print <<VERSION;

    Version: $SCRIPT-$VERSION

VERSION
    exit(1);

}

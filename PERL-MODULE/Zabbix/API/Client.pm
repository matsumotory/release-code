#!/usr/bin/perl
package Zabbix::API::Client;

use strict;
use warnings;
use JSON;
use LWP::UserAgent;
use Sys::Hostname;
use base "Zabbix::API::Super";
use base qw(

    Zabbix::API::Client::Operation
    Zabbix::API::Client::File

);

__PACKAGE__->mk_accessors(qw(

   UserAgent
   Request  
   Count    
   Auth     

));

$ENV{'IFS'}     = '' if $ENV{'IFS'};
$ENV{'PATH'}    = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin';
$ENV{'LC_TIME'} = 'C';
umask(022);

sub new {

    my ($class, %args) = @_;

    my $json_url    = $args{url};
    my $user_agent  = $args{user_agent};


    my $self =  bless {

        UserAgent           =>  undef,
        Request             =>  undef,
        Count               =>  1,
        Auth                =>  undef,

        # Base.pm properties
        debug               =>  (exists $args{debug})            ? $args{debug}             :   0,
        info                =>  (exists $args{info})             ? $args{info}              :   0,
        warn                =>  (exists $args{warn})             ? $args{warn}              :   0,
        error               =>  (exists $args{error})            ? $args{error}             :   0,
        irc_owner           =>  (exists $args{irc_owner})        ? $args{irc_owner}         :   'ZabbixSystem',
        irc_channel         =>  (exists $args{irc_channel})      ? $args{irc_channel}       :   '#TEST:*.jp',
        irc_script          =>  (exists $args{irc_script})       ? $args{irc_script}        :   './bin/irc-write.pl',
        irc_server          =>  (exists $args{irc_server})       ? $args{irc_server}        :   '256.256.256.256',
        log_file            =>  (exists $args{log_file})         ? $args{log_file}          :   "/tmp/tool-$ENV{USER}.log",
        tool_name           =>  (exists $args{tool_name})        ? $args{tool_name}         :   'Zabbix_tool',
        syslog_type         =>  (exists $args{syslog_type})      ? $args{syslog_type}       :   'Zabbix_operation',
        syslog_priority     =>  (exists $args{syslog_priority})  ? $args{syslog_priority}   :   'local3.notice',
        mailfrom            =>  (exists $args{mailfrom})         ? $args{mailfrom}          :   'Zabbix_operation@'.hostname(),
        pid_file            =>  (exists $args{pid_file})         ? $args{pid_file}          :   "/tmp/zabbix_tool-$ENV{USER}.pid",
        lock_file           =>  (exists $args{lock_file})        ? $args{lock_file}         :   "/tmp/zabbix_tool-$ENV{USER}.lock",
        user_name           =>  (exists $args{user_name})        ? $args{user_name}         :   $ENV{USER},
        lock_fd             =>  undef,
        command             =>  undef,
        already_running     =>  0,

    }, $class;

    my ($ua, $req, $res, $auth);

    $ua = LWP::UserAgent->new;
    $ua->agent($user_agent);

    $req = HTTP::Request->new(POST => $json_url);
    $req->content_type('application/json-rpc');
    $req->content(encode_json({

        jsonrpc     =>  "2.0",
        method      =>  "user.authenticate",
        params      =>  {
                            user        => $args{user},
                            password    => $args{pass},
                        },
        id          =>  1,

    }));

    $res = $ua->request($req);
    $self->error_record("Can't connect to Zabbix API." . $res->status_line) if !$res->is_success;
    $auth = decode_json($res->content)->{'result'};

    $self->Request($req);
    $self->UserAgent($ua);
    $self->Auth($auth);
    $self->debug_record(__PACKAGE__." [new] executed.", $self->{info});
    $self->initialization;

    return $self;
}

sub initialization {

    my $self = shift;

}

1;

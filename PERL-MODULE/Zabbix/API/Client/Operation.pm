#!/usr/bin/perl
#############################################################################################
#
# package
#
#############################################################################################
package Zabbix::API::Client::Operation;

use JSON;
use Encode;
use Data::Dump qw(dump);

our $VERSION = 0.01;

sub api_operation {

    my ($self, $method, $object, $params) = @_;

    my $req_json = {

        jsonrpc => "2.0",
        method  => "$object.$method",
        params  => $params,
        auth    => $self->Auth,
        id      => $self->next_id,

    };
    my ($req, $res, $response_data);

    $self->debug_record("Requset to Zabbix API. Request JSON data is " . dump($req_json));
    $req = $self->Request;
    $req->content(encode_json($req_json));

    $res = $self->UserAgent->request($req);
    $self->error_record("Can't connect to Zabbix API." . $res->status_line) if !$res->is_success;

    $response_data = decode_json($res->content);
    $self->debug_record("Response from Zabbix API. Response JSON data is " . dump($response_data));
    $self->error_record("JSON Object exec failed. Response is " . dump($response_data)) if !exists $response_data->{result};

    return $response_data;
}

sub next_id {

    my $self = shift;

    my $id = $self->Count;

    return ++$id;
}

1;

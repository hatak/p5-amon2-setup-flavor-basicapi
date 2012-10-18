use strict;
use warnings FATAL => 'all';
use utf8;

package Amon2::Setup::Flavor::BasicAPI;
use parent qw(Amon2::Setup::Flavor::Basic);
our $VERSION = '0.01';

sub create_web_pms {
    my ($self) = @_;

    $self->write_file('lib/<<PATH>>/Web.pm', <<'...', { xslate => $self->create_view() });
package <% $module %>::Web;
use strict;
use warnings;
use utf8;
use parent qw/<% $module %> Amon2::Web/;
use File::Spec;

# dispatcher
use <% $module %>::Web::Dispatcher;
sub dispatch {
    return (<% $module %>::Web::Dispatcher->dispatch($_[0]) or die "response is not generated");
}

# render
sub render {
    my ($self, @render_args) = @_;

    my $ext = $self->req->{env}{PATH_EXT};
    if (defined $ext && $ext eq 'json') {
        shift @render_args;
        $self->render_json(@render_args);
    } else {
        $self->next::method(@render_args);
    }
}

<% $xslate %>

# load plugins
__PACKAGE__->load_plugins(
    'Web::FillInFormLite',
    'Web::CSRFDefender',
    '+<% $module %>::Web::JSON',
);

# for your security
__PACKAGE__->add_trigger(
    AFTER_DISPATCH => sub {
        my ( $c, $res ) = @_;

        # http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-v-comprehensive-protection.aspx
        $res->header( 'X-Content-Type-Options' => 'nosniff' );

        # http://blog.mozilla.com/security/2010/09/08/x-frame-options/
        $res->header( 'X-Frame-Options' => 'DENY' );

        # Cache control.
        $res->header( 'Cache-Control' => 'private' );
    },
);

__PACKAGE__->add_trigger(
    BEFORE_DISPATCH => sub {
        my ( $c ) = @_;

        # check and split <path_info>[.<ext_ext>]
        if ($c->req->path =~ /(\/.+)\.(\w+)$/) {
            $c->req->{env}{PATH_INFO} = $1;
            $c->req->{env}{PATH_EXT} = $2;
        }

        return;
    },
);

1;
...

    $self->write_file("lib/<<PATH>>/Web/Dispatcher.pm", <<'...');
package <% $module %>::Web::Dispatcher;
use strict;
use warnings;
use utf8;
use Amon2::Web::Dispatcher::Lite;

any '/' => sub {
    my ($c) = @_;
    return $c->render('index.tt');
};

post '/account/logout' => sub {
    my ($c) = @_;
    $c->session->expire();
    return $c->redirect('/');
};

1;
...

    $self->write_file("lib/<<PATH>>/Web/JSON.pm", <<'...');
package <% $module %>::Web::JSON;
use strict;
use warnings;
use JSON 2 qw/encode_json/;
use Amon2::Util ();

my $_JSON = JSON->new()->ascii(1)->convert_blessed(1);

my %_ESCAPE = (
    '+' => '\\u002b', # do not eval as UTF-7
    '<' => '\\u003c', # do not eval as HTML
    '>' => '\\u003e', # ditto.
);

sub init {
    my ($class, $c, $conf) = @_;
    unless ($c->can('render_json')) {
        Amon2::Util::add_method($c, 'render_json', \&_render_json);
    }
}

sub _render_json {
    my ($c, $stuff) = @_;

    # for IE7 JSON venularity.
    # see http://www.atmarkit.co.jp/fcoding/articles/webapp/05/webapp05a.html
    my $output = $_JSON->encode($stuff);
    $output =~ s!([+<>])!$_ESCAPE{$1}!g;

    # defense from JSON hijacking
    if ((!$c->request->header('X-Requested-With')) && ($c->req->user_agent||'') =~ /android/i && defined $c->req->header('Cookie') && ($c->req->method||'GET') eq 'GET') {
        my $res = $c->create_response(403);
        $res->content_type('text/html; charset=utf-8');
        $res->content("Your request is maybe JSON hijacking.\nIf you are not a attacker, please add 'X-Requested-With' header to each request.");
        $res->content_length(length $res->content);
        return $res;
    }

    my $res = $c->create_response(200);

    my $encoding = $c->encoding();
    $encoding = lc($encoding->mime_name) if ref $encoding;
    $res->content_type("application/json; charset=$encoding");

    # add UTF-8 BOM if the client is Safari
    if ( ( $c->req->user_agent || '' ) =~ m/Safari/ and $encoding eq 'utf-8' ) {
        $output = "\xEF\xBB\xBF" . $output;
    }

    $res->header( 'X-Content-Type-Options' => 'nosniff' ); # defense from XSS
    $res->content_length(length($output));
    $res->body($output);

    return $res;
}

1;
__END__

=encoding utf-8

=head1 NAME

<% $module %>::Web::JSON - JSON plugin

=head1 SYNOPSIS

    use Amon2::Lite;

    __PACKAGE__->load_plugins(qw/+<% $module %>::Web::JSON/);

    get '/' => sub {
        my $c = shift;
        return $c->render_json(+{foo => 'bar'});
    };

    __PACKAGE__->to_app();

=head1 DESCRIPTION

This is a JSON plugin based on L<Amon2::Web::Plugin::JSON>.

...
}

1;
__END__

=head1 NAME

Amon2::Setup::Flavor::BasicAPI - Basic flavor with JSON API for Amon2

=head1 SYNOPSIS

    % amon2-setup.pl --flavor=BasicAPI MyApp

=head1 DESCRIPTION

This is customized basic flavor for Amon2.

=head1 AUTHOR

Hisashi HATAKEYAMA E<lt>id.hatak@gmail.comE<gt>

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

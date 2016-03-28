# vim:set sw=4 ts=4 sts=4 ft=perl expandtab:
package Lstu::Command::migrate_from_sqlite;
use Mojo::Base 'Mojolicious::Commands';
use FindBin qw($Bin);
use File::Spec qw(catfile cat dir);
use File::Path qw(make_path);
use LstuModel;
use SessionModel;
use Mojo::Collection;
use Lstu;
use Term::ProgressBar;
use Term::ANSIColor;
use File::Copy qw(move);

has description => 'Migrate data from SQLite database to PostgreSQL.';
has usage => sub { shift->extract_usage };
has message    => sub { shift->extract_usage . "\nMigrate data from SQLite database to PostgreSQL:\n" };
has namespaces => sub { ['Lstu::Command::theme'] };

sub run {
    my $c    = shift->app(Lstu->new)->app;
    $c->plugin('Config' => { default => { db_path => 'lstu.db' } });

    my $before = $c->pg->db->query('SELECT count(short) FROM lstu WHERE url IS NOT NULL')->array->[0];
    say colored('We have '.$before.' non null records in the PostgreSQL database.', 'bold blue');

    # Data migration (from SQLite to PostgreSQL)
    if (-e $c->config('db_path')) {
        my $urls = Mojo::Collection->new(
            LstuModel::Lstu->select('WHERE url IS NOT NULL')
        );

        my $progress = Term::ProgressBar->new(
            {
                name  => 'Migrating '.$urls->size.' records from SQLite',
                count => $urls->size
            }
        );
        my $tx = $c->pg->db->begin;
        $urls->each( sub {
                my ($url, $num) = @_;
                $c->pg->db->query('INSERT INTO lstu (short, url, counter, timestamp) VALUES (?, ?, ?, ?)', ($url->short, $url->url, $url->counter, $url->timestamp));
                $progress->update();
            }
        );
        my $now = $c->pg->db->query('SELECT count(short) FROM lstu WHERE url IS NOT NULL')->array->[0];
        say colored('We now have '.$now.' non null records in the PostgreSQL database.', 'bold blue');
        if ($now - $before == $urls->size) {
            say colored('All the records have been successfully migrated', 'bold green');
            $tx->commit;
            move($c->config('db_path'), $c->config('db_path').'.bak');
            say 'I moved '.$c->config('db_path').' to '.$c->config('db_path').'.bak';
        } else {
            say colored('There have been a problem during the migration: only '.($now - $before).' records have been migrated.', 'bold red');
            say colored('I prefer to rollback the migration (no data have been migrated)', 'bold red');
        }
    } else {
        say colored('SQLite database not found ('.$c->config('db_path').')', 'bold orange');
        exit 1;
    }
}

=encoding utf8

=head1 NAME

Lstu::Command::migrate_from_sqlite - Migrate data from SQLite database to PostgreSQL.

=head1 SYNOPSIS

  Usage: script/lstu migrate_from_sqlite

=cut

1;

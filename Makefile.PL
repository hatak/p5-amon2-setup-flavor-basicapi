use inc::Module::Install;
name 'Amon2-Setup-Flavor-BasicAPI';
all_from 'lib/Amon2/Setup/Flavor/BasicAPI.pm';

# requires '';

tests 't/*.t';
author_tests 'xt';

test_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;

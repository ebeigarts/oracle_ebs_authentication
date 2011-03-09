Oracle E-Business Suite authentication
======================================

This plugin provides Oracle E-Business Suite user authentication functionality.

## Installation

    gem install oracle_ebs_authentication

## Setup

1. Grant execute on `apps.fnd_encrypted_pwd` to your database user.
2. Setup [ruby-plsql](https://rubygems.org/gems/ruby-plsql) connection for your database.

## Examples

Simple example how to use the plugin for Oracle E-Business Suite user authentication:

    authenticator = OracleEbsAuthentication::Authenticator.new
    if authenticator.validate_user_password(username, password)
      FndUser.find_by_username(username.upcase)
    end

See other usage examples in RSpec examples in `spec/`.

## Credits

Copyright (C) 2007-2011 Raimonds Simanovskis, Edgars Beigarts.

Oracle E-Business Suite authentication encryption algorythm was taken from
[Jira eBusiness Suite Authenticator](http://code.google.com/p/jebusinessauth/) and
rewritten in Ruby by Raimonds Simanovskis.

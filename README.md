Oracle E-Business Suite authentication
======================================

This plugin provides Oracle E-Business Suite user authentication functionality.

## Installation

To install this plugin for your Ruby on Rails application do the following:

    gem install oracle_ebs_authentication

Grant execute on `apps.fnd_encrypted_pwd` to your database user.

## Examples

Simple example how to use the plugin for Oracle E-Business Suite user authentication:

    database_name = ActiveRecord::Base.connection.current_database
    authenticator = OracleEbsAuthentication::Authenticator.new(database_name)
    if authenticator.validate_user_password(login, password)
      # user authenticated
    else
      # authentication failed
    end

See other usage examples in RSpec examples in spec/oracle_ebs_authentication_spec.rb

## Credits

Copyright (C) 2007-2011 Raimonds Simanovskis, Edgars Beigarts.

Oracle E-Business Suite authentication encryption algorythm was taken from
[Jira eBusiness Suite Authenticator](http://code.google.com/p/jebusinessauth/) and
rewritten in Ruby by Raimonds Simanovskis.

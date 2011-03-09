# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)

require "oracle_ebs_authentication/version"

Gem::Specification.new do |s|
  s.name        = "oracle_ebs_authentication"
  s.version     = OracleEbsAuthentication::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Edgars Beigarts"]
  s.email       = "1@wb4.lv"
  s.homepage    = "http://github.com/ebeigarts/oracle_ebs_authentication"
  s.description = %q{This plugin provides Oracle E-Business Suite user authentication functionality.}
  s.summary     = s.description

  s.rubygems_version = "1.3.6"

  s.add_runtime_dependency "activesupport", ">= 2.2"
  s.add_runtime_dependency "ruby-plsql", ">= 0.4.2"

  s.add_development_dependency "rake"
  s.add_development_dependency "rspec", ["~> 2.5.0"]
  s.add_development_dependency "ruby-oci8", ["~> 2.0.4"]

  s.files          = Dir.glob("{lib,spec}/**/*") + %w(README.md LICENSE)
  s.require_paths  = ["lib"]
end

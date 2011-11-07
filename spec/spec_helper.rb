$:.unshift File.dirname(__FILE__) + '/../lib'

require "oracle_ebs_authentication"

DATABASE_NAME     = ENV['DATABASE_NAME'] || 'VIS'
DATABASE_USERNAME = ENV['DATABASE_USERNAME'] || 'APPS'
DATABASE_PASSWORD = ENV['DATABASE_PASSWORD'] || 'APPS'

require "ruby_plsql"

module OracleEbsAuthentication
  class Authenticator
    def initialize
      @security = OracleEbsAuthentication::Security.new
    end

    def get_fnd_password(username, password)
      username &&= username.upcase
      password &&= password.mb_chars.upcase.to_s
      result = plsql.apps.fnd_security_pkg.fnd_encrypted_pwd(username, nil, nil, nil)
      if result[:p_password]
        @security.decrypt(username + "/" + password, result[:p_password], false)
      end
    rescue OCIError
      nil
    end

    def validate_user_password(username, password)
      if username && password
        !! get_fnd_password(username, password)
      end
    end
  end
end

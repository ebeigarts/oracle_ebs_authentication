# OracleEbsAuthentication
require "oci8"
require "security"

module OracleEbsAuthentication

  class Authenticator
    attr_accessor :user, :password
    attr_reader :user_responsibilities, :user_id, :email
    
    def initialize(db_name, gw_user="APPLSYSPUB", gw_password="PUB", fnd_name="APPS",
                  db_server_id=nil, module_name="FNDPUB")
      @db_name = db_name
      @gw_user = gw_user
      @gw_password = gw_password
      @fnd_name = fnd_name
      @db_server_id = db_server_id
      @module_name = module_name
      @security = OracleEbsAuthentication::Security.new
    end
    
    def get_fnd_password(user = nil, password = nil)
      @user = user.upcase unless user.blank?
      @password = password.upcase unless password.blank?
      if gw_connect
        begin
          cursor = @gw_connection.parse(<<-EOS
          BEGIN
            fnd_security_pkg.fnd_encrypted_pwd(:p_user,:p_server_id,:p_user_id,:p_efp,:p_module);
          END;
          EOS
          )
          cursor.bind_param(':p_user', @user, String, 100)
          cursor.bind_param(':p_server_id', @db_server_id, String, 100)
          cursor.bind_param(':p_user_id', nil, String, 100)
          cursor.bind_param(':p_efp', nil, String, 100)
          cursor.bind_param(':p_module', @module_name, String, 100)
          cursor.exec
          @user_id = cursor[':p_user_id']
          @efp = cursor[':p_efp']
        rescue OCIError
          @user_id = nil
          @efp = nil
        end
        gw_disconnect
        @fnd_password = @efp ? @security.decrypt(@user.upcase + "/" + @password.upcase, @efp, false) : nil
      else
        @fnd_password = nil
      end
    end
    
    def validate_user_password(user = nil, password = nil)
      get_fnd_password(user, password) if user && password
      return nil unless @fnd_password
      if fnd_connect
        cursor = @fnd_connection.parse(<<-EOS
        SELECT encrypted_user_password, email_address
        FROM fnd_user
        WHERE user_id = :p_user_id
        EOS
        )
        cursor.bind_param(':p_user_id', @user_id.to_i, Fixnum)
        cursor.exec
        r = cursor.fetch
        @eup, @email = r[0], r[1]
        cursor.close

        @user_responsibilities = []
        @fnd_connection.exec("SELECT r.responsibility_name
        FROM fnd_user_resp_groups_all ur,
             fnd_responsibility_vl r
        WHERE ur.user_id = :p_user_id
        AND TRUNC(SYSDATE) BETWEEN NVL(ur.start_date,TRUNC(SYSDATE)) AND NVL(ur.end_date, TRUNC(SYSDATE))
        AND ur.responsibility_id = r.responsibility_id", @user_id.to_i) do |r|
          @user_responsibilities << r[0]
        end

        fnd_disconnect

        @security.decrypt(@fnd_password, @eup, false) == @password.upcase
      else
        false
      end
    end
    
    private
    
    def gw_connect
      if @gw_connection = OCI8.new(@gw_user, @gw_password, @db_name)
        true
      else
        false
      end
    rescue OCIError
      false
    end

    def gw_disconnect
      @gw_connection.logoff 
    end

    def fnd_connect
      if @fnd_connection = OCI8.new(@fnd_name, @fnd_password, @db_name)
        return true
      else
        return false
      end
    rescue OCIError
      false
    end

    def fnd_disconnect
      @fnd_connection.logoff 
    end

  end

end

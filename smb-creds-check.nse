description = [[ 
**Windows Credentials Checker**
This script should search if a set of credentials are valid for a range of Windows hosts.

The code is mainly a modified version of smb-brute.nse (written by Ron Bowes).

The code is unfinished and insufficiently tested. Reporting is not implemented.
See also:
    http://www.skullsecurity.org/blog/2009/bruteforcing-windows-tips-and-tricks
    Ron's SANS paper
]]

---
--@usage
-- nmap -p 445 -dd  --script smb-creds-check.nse --script-args 'userdb=users.txt,passdb=pass.txt' <host>

categories = {"intrusive", "brute"}

require 'smb'
require 'unpwdb'

hostrule = function(host)
    return smb.get_port(host) ~= nil
end

---The possible result codes. These are simplified from the actual codes that SMB returns. 
local results =
{
    SUCCESS             =  1, -- Login was successful
    GUEST_ACCESS        =  2, -- Login was successful, but was granted guest access
    NOT_GRANTED         =  3, -- Password was correct, but user wasn't allowed to log in (often happens with blank passwords)
    DISABLED            =  4, -- Password was correct, but user's account is disabled
    EXPIRED             =  5, -- Password was correct, but user's account is expired
    CHANGE_PASSWORD     =  6, -- Password was correct, but user can't log in without changing it
    ACCOUNT_LOCKED      =  7, -- User's account is locked out (hopefully not by us!)
    ACCOUNT_LOCKED_NOW  =  8, -- User's account just became locked out (oops!)
    FAIL                =  9, -- User's password was incorrect
    INVALID_LOGON_HOURS = 10, -- Password was correct, but user's account has logon time restrictions in place
    INVALID_WORKSTATION = 11  -- Password was correct, but user's account has workstation restrictions in place
}

---Strings for debugging output
local result_short_strings = {}
result_short_strings[results.SUCCESS]             = "SUCCESS"
result_short_strings[results.GUEST_ACCESS]        = "GUEST_ACCESS"
result_short_strings[results.NOT_GRANTED]         = "NOT_GRANTED"
result_short_strings[results.DISABLED]            = "DISABLED"
result_short_strings[results.EXPIRED]             = "EXPIRED"
result_short_strings[results.CHANGE_PASSWORD]     = "CHANGE_PASSWORD"
result_short_strings[results.ACCOUNT_LOCKED]      = "LOCKED"
result_short_strings[results.ACCOUNT_LOCKED_NOW]  = "LOCKED_NOW"
result_short_strings[results.FAIL]                = "FAIL"
result_short_strings[results.INVALID_LOGON_HOURS] = "INVALID_LOGON_HOURS"
result_short_strings[results.INVALID_WORKSTATION] = "INVALID_WORKSTATION"


---The strings that the user will see
local result_strings = {}
result_strings[results.SUCCESS]              = "Valid credentials"
result_strings[results.GUEST_ACCESS]         = "Valid credentials, account granted guest access only"
result_strings[results.NOT_GRANTED]          = "Valid credentials, but account wasn't allowed to log in (often happens with blank passwords)"
result_strings[results.DISABLED]             = "Valid credentials, account disabled"
result_strings[results.EXPIRED]              = "Valid credentials, account expired"
result_strings[results.CHANGE_PASSWORD]      = "Valid credentials, password must be changed at next logon"
result_strings[results.ACCOUNT_LOCKED]       = "Valid credentials, account locked (hopefully not by us!)"
result_strings[results.ACCOUNT_LOCKED_NOW]   = "Valid credentials, account just became locked (oops!)"
result_strings[results.FAIL]                 = "Invalid credentials"
result_strings[results.INVALID_LOGON_HOURS]  = "Valid credentials, account cannot log in at current time"
result_strings[results.INVALID_WORKSTATION]  = "Valid credentials, account cannot log in from current host"



---Stops the session, if one exists. This can be called as frequently as needed, it'll just return if no
-- session is present, but it should generally be paired with a <code>restart_session</code> call. 
--@param hostinfo The hostinfo table. 
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined. 
local function stop_session(hostinfo)
    local status, err

    if(hostinfo['smbstate'] ~= nil) then
        stdnse.print_debug(2, "smb-brute: Stopping the SMB session")
        status, err = smb.stop(hostinfo['smbstate'])
        if(status == false) then
            return false, err
        end

        hostinfo['smbstate'] = nil
    end


    return true
end


---Starts or restarts a SMB session with the host. Although this will automatically stop a session if
-- one exists, it's a little cleaner to pair this with a <code>stop_session</code> call. 
--@param hostinfo The hostinfo table. 
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined. 
local function restart_session(hostinfo)
    local status, err, smbstate

    -- Stop the old session, if it exists
    stop_session(hostinfo)

    stdnse.print_debug(2, "smb-brute: Starting the SMB session")
    status, smbstate = smb.start_ex(hostinfo['host'], true, nil, nil, nil, true)
    if(status == false) then
        return false, smbstate
    end

    hostinfo['smbstate'] = smbstate

    return true
end

---Generates a random string of the requested length. This can be used to check how hosts react to 
-- weird username/password combinations. 
--@param length (optional) The length of the string to return. Default: 8. 
--@param set    (optional) The set of letters to choose from. Default: upper, lower, numbers, and underscore. 
--@return The random string. 
local function get_random_string(length, set)
    if(length == nil) then
        length = 8
    end

    if(set == nil) then
        set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
    end

    local str = ""

    for i = 1, length, 1 do
        local random = math.random(#set)
        str = str .. string.sub(set, random, random)
    end

    return str
end


---Attempts to log into an account, returning one of the <code>results</code> constants. Will always return to the 
-- state where another login can be attempted. Will also differentiate between a hash and a password, and choose the 
-- proper login method (unless overridden). Will interpret the result as much as possible. 
--
-- The session has to be active (ie, <code>restart_session</code> has to be called) before calling this function. 
--
--@param hostinfo The hostinfo table. 
--@param username The username to try. 
--@param password The password to try. 
--@param logintype [optional] The logintype to use. Default: <code>get_type</code> is called. If <code>password</code>
--       is a hash, this is ignored. 
--@return Result, an integer value from the <code>results</code> constants. 
local function check_login(hostinfo, username, password, logintype)
    local result
    local domain = ""
    local smbstate = hostinfo['smbstate']
    if(logintype == nil) then
        logintype = get_type(hostinfo)
    end

    stdnse.print_debug(1, "=== Trying login: %s/%s", username, password)

    -- Determine if we have a password hash or a password
    if(#password == 32 or #password == 64 or #password == 65) then
        -- It's a hash (note: we always use NTLM hashes)
        status, err   = smb.start_session(smbstate, smb.get_overrides(username, domain, nil, password, "ntlm"), false)
    else
        status, err   = smb.start_session(smbstate, smb.get_overrides(username, domain, password, nil, logintype), false)
    end
   
    if(status == true) then
        if(smbstate['is_guest'] == 1) then
            result = results.GUEST_ACCESS
        else
            result = results.SUCCESS
        end

        smb.logoff(smbstate)
    else
        if(err == "NT_STATUS_LOGON_TYPE_NOT_GRANTED") then
            result = results.NOT_GRANTED
        elseif(err == "NT_STATUS_ACCOUNT_LOCKED_OUT") then
            result = results.ACCOUNT_LOCKED
        elseif(err == "NT_STATUS_ACCOUNT_DISABLED") then
            result = results.DISABLED
        elseif(err == "NT_STATUS_PASSWORD_MUST_CHANGE") then
            result = results.CHANGE_PASSWORD
        elseif(err == "NT_STATUS_INVALID_LOGON_HOURS") then
            result = results.INVALID_LOGON_HOURS
        elseif(err == "NT_STATUS_INVALID_WORKSTATION") then
            result = results.INVALID_WORKSTATION
        elseif(err == "NT_STATUS_ACCOUNT_EXPIRED") then
            result = results.EXPIRED
        else
            result = results.FAIL
        end
    end

    io.write(string.format("Result: %s\n\n", result_strings[result]))

    return result
end


---Initializes and returns the hostinfo table. This includes queuing up the username and password lists, determining
-- the server's operating system,  and checking the server's response for invalid usernames/invalid passwords. 
--
--@param host The host object. 
local function initialize(host)
    local os, result
    local status, bad_lockout_policy_result
    local hostinfo = {}

    hostinfo['host'] = host
    hostinfo['invalid_usernames'] = {}
    hostinfo['locked_usernames'] = {}
    hostinfo['accounts'] = {}
    hostinfo['special_password'] = 1

    -- Get the OS (identifying windows versions tells us which hash to use)
    result, os = smb.get_os(host)
    if(result == false or os['os'] == nil) then
        hostinfo['os'] = "<Unknown>"
    else
        hostinfo['os'] = os['os']
    end
    stdnse.print_debug(1, "smb-brute: Remote operating system: %s", hostinfo['os'])

    -- Check lockout policy
    -- status, bad_lockout_policy_result = bad_lockout_policy(host)
    -- if(not(status)) then
    --  stdnse.print_debug(1, "smb-brute: WARNING: couldn't determine lockout policy: %s", bad_lockout_policy_result)
    -- else
    --  if(bad_lockout_policy_result) then
    --      return false, "Account lockouts are enabled on the host. To continue (and risk lockouts), add --script-args=smblockout=1 -- for more information, run smb-enum-domains."
    --  end
    -- end

    -- Attempt to enumerate users
    -- stdnse.print_debug(1, "smb-brute: Trying to get user list from server")
    -- hostinfo['have_user_list'], _, hostinfo['user_list'] = msrpc.get_user_list(host)
    -- hostinfo['user_list_index'] = 1
    -- if(hostinfo['have_user_list'] and #hostinfo['user_list'] == 0) then
        hostinfo['have_user_list'] = false
    -- end

    -- If the enumeration failed, try using the built-in list
    if(not(hostinfo['have_user_list'])) then
        stdnse.print_debug(1, "smb-brute: Couldn't enumerate users (normal for Windows XP and higher), using unpwdb initially")
        status, hostinfo['user_list_default'] = unpwdb.usernames()
        if(status == false) then
            return false, "Couldn't open username file"
        end
    end

    -- Open the password file
    stdnse.print_debug(1, "smb-brute: Opening password list")
    status, hostinfo['password_list'] = unpwdb.passwords()
    if(status == false) then
        return false, "Couldn't open password file"
    end

    -- Start the SMB session
    stdnse.print_debug(1, "smb-brute: Starting the initial SMB session")
    status, err = restart_session(hostinfo)
    if(status == false) then
        stop_session(hostinfo)
        return false, err
    end

    -- Some hosts will accept any username -- check for this by trying to log in with a totally random name. If the 
    -- server accepts it, it'll be impossible to bruteforce; if it gives us a weird result code, we have to remember
    -- it. 
    -- hostinfo['invalid_username'] = check_login(hostinfo, get_random_string(8), get_random_string(8), "ntlm")
    -- hostinfo['invalid_password'] = check_login(hostinfo, "Administrator",      get_random_string(8), "ntlm")
    hostinfo['invalid_username'] = check_login(hostinfo, get_random_string(8), get_random_string(8), "ntlm")
    hostinfo['invalid_password'] = check_login(hostinfo, "Administrator",      get_random_string(8), "ntlm")

    stdnse.print_debug(1, "smb-brute: Server's response to invalid usernames: %s", result_short_strings[hostinfo['invalid_username']])
    stdnse.print_debug(1, "smb-brute: Server's response to invalid passwords: %s", result_short_strings[hostinfo['invalid_password']])

    -- If either of these comes back as success, there's no way to tell what's valid/invalid
    if(hostinfo['invalid_username'] == results.SUCCESS) then
        stop_session(hostinfo)
        return false, "Invalid username was accepted; unable to bruteforce"
    end
    if(hostinfo['invalid_password'] == results.SUCCESS) then
        stop_session(hostinfo)
        return false, "Invalid password was accepted; unable to bruteforce"
    end

    -- Print a message to the user if we can identify passwords
    if(hostinfo['invalid_username'] ~= hostinfo['invalid_password']) then
        stdnse.print_debug(1, "smb-brute: Invalid username and password response are different, so identifying valid accounts is possible")
    end

    -- Print a warning message if invalid_username and invalid_password go to the same thing that isn't FAIL
    if(hostinfo['invalid_username'] ~= results.FAIL and hostinfo['invalid_username'] == hostinfo['invalid_password']) then
        stdnse.print_debug(1, "smb-brute: WARNING: Difficult to recognize invalid usernames/passwords; may not get good results")
    end

    -- Restart the SMB connection so we have a clean slate
    stdnse.print_debug(1, "smb-brute: Restarting the session before the bruteforce")
    status, err = restart_session(hostinfo)
    if(status == false) then
        stop_session(hostinfo)
        return false, err
    end

    -- Stop the SMB session (we're going to let the scripts look after their own sessions)
    stop_session(hostinfo)

    -- Return the results
    return true, hostinfo
end


---Attempts to validate the current list of usernames by logging in with a blank password, marking invalid ones (and ones that had
-- a blank password). Determining the validity of a username works best if invalid usernames are redirected to 'guest'. 
--
-- If a username accepts the blank password, a random password is tested. If that's accepted as well, the account is marked as 
-- accepting any password (the 'guest' account is normally like that). 
--
-- This also checks whether the server locks out users, and raises the lockout threshold of the first user (see the 
-- <code>check_lockouts</code> function for more information on that. If accounts on the system are locked out, they aren't
-- checked. 
--
--@param hostinfo The hostinfo table. 
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined. 
local function validate_usernames(hostinfo)
    local status, err
    local result
    local username, password

    stdnse.print_debug(1, "smb-brute: Checking which account names exist (based on what goes to the 'guest' account)")

    -- Start a session
    status, err = restart_session(hostinfo)
    if(status == false) then
        return false, err
    end

    -- Make sure we start at the beginning
    reset_username(hostinfo)

    username = get_next_username(hostinfo)
    while(username ~= nil) do
        result = check_login(hostinfo, username, "", "ntlm")

        if(result ~= hostinfo['invalid_password'] and result == hostinfo['invalid_username']) then
            -- If the account matches the value of 'invalid_username', but not the value of 'invalid_password', it's invalid
            stdnse.print_debug(1, "smb-brute: Blank password for '%s' -> '%s' (invalid account)", username, result_short_strings[result])
            hostinfo['invalid_usernames'][username] = true

        elseif(result == hostinfo['invalid_password']) then

            -- If the account matches the value of 'invalid_password', and 'invalid_password' is reliable, it's probably valid
            if(hostinfo['invalid_username'] ~= results.FAIL and hostinfo['invalid_username'] == hostinfo['invalid_password']) then
                stdnse.print_debug(1, "smb-brute: Blank password for '%s' => '%s' (can't determine validity)", username, result_short_strings[result])
            else
                stdnse.print_debug(1, "smb-brute: Blank password for '%s' => '%s' (probably valid)", username, result_short_strings[result])
            end

        elseif(result == results.ACCOUNT_LOCKED) then
            -- If the account is locked out, don't try it
            hostinfo['locked_usernames'][username] = true
            stdnse.print_debug(1, "smb-brute: Blank password for '%s' => '%s' (locked out)", username, result_short_strings[result])

        elseif(result == results.FAIL) then
            -- If none of the standard options work, check if it's FAIL. If it's FAIL, there's an error somewhere (probably, the 
            -- 'administrator' username is changed so we're getting invalid data). 
            stdnse.print_debug(1, "smb-brute: Blank password for '%s' => '%s' (may be valid)", username, result_short_strings[result])

        else
            -- If none of those came up, either the password is legitimately blank, or any account works. Figure out what! 
            local new_result = check_login(hostinfo, username, get_random_string(14), "ntlm")
            if(new_result == result) then
                -- Any password works (often happens with 'guest' account)
                stdnse.print_debug(1, "smb-brute: All passwords accepted for %s (goes to %s)", username, result_short_strings[result])
                status, err = found_account(hostinfo, username, "<anything>", result)
                if(status == false) then
                    return false, err
                end
            else
                -- Blank password worked, but not random one
                status, err = found_account(hostinfo, username, "", result)
                if(status == false) then
                    return false, err
                end
            end
        end

        username = get_next_username(hostinfo)
    end

    -- Start back at the beginning of the list
    reset_username(hostinfo)

    -- Check for lockouts
    -- test_lockouts(hostinfo)

    -- Stop the session
    stop_session(hostinfo)

    return true
end

---Decides which login type to use (lanman, ntlm, or other). Designed to keep things consistent. 
--@param hostinfo The hostinfo table. 
--@return A string representing the login type to use (that can be passed to SMB functions). 
local function get_type(hostinfo)
    -- Check if the user requested a specific type
    if(nmap.registry.args.smbtype ~= nil) then
        return nmap.registry.args.smbtype
    end

    -- Otherwise, base the type on the operating system (TODO: other versions of Windows (7, 2008))
    -- 2k8 example: "Windows Server (R) 2008 Datacenter without Hyper-V 6001 Service Pack 1"
    if(string.find(string.lower(hostinfo['os']), "vista") ~= nil) then
        return "ntlm"
    elseif(string.find(string.lower(hostinfo['os']), "2008") ~= nil) then
        return "ntlm"
    elseif(string.find(string.lower(hostinfo['os']), "Windows 7") ~= nil) then
        return "ntlm"
    end

    return "lm"
end

---Determines whether or not a login was successful, based on what's known about the server's settings. This 
-- is fairly straight forward, but has a couple little tricks. 
--
--@param hostinfo The hostinfo table. 
--@param result   The result code. 
--@return <code>true</code> if the password used for logging in was correct, <code>false</code> otherwise. Keep
--        in mind that this doesn't imply the login was successful (only results.SUCCESS indicates that), rather
--        that the password was valid. 

function is_positive_result(hostinfo, result)
    -- If result is a FAIL, it's always bad
    if(result == results.FAIL) then
        return false
    end

    -- If result matches what we discovered for invalid passwords, it's always bad
    if(result == hostinfo['invalid_password']) then
        return false
    end

    -- If result was ACCOUNT_LOCKED, it's always bad (locked accounts should already be taken care of, but this
    -- makes the function a bit more generic)
    if(result == results.ACCOUNT_LOCKED) then
        return false
    end

    -- Otherwise, it's good
    return true
end

---Determines whether or not a login was "bad". A bad login is one where an account becomes locked out. 
--
--@param hostinfo The hostinfo table. 
--@param result   The result code. 
--@return <code>true</code> if the password used for logging in was correct, <code>false</code> otherwise. Keep
--        in mind that this doesn't imply the login was successful (only results.SUCCESS indicates that), rather
--        that the password was valid. 

function is_bad_result(hostinfo, result)
    -- If result is LOCKED, it's always bad. 
    if(result == results.ACCOUNT_LOCKED or result == results.ACCOUNT_LOCKED_NOW) then
        return true
    end

    -- Otherwise, it's good
    return false
end


--_G.TRACEBACK = TRACEBACK or {}
action = function(host)
--  TRACEBACK[coroutine.running()] = true;

    local status, result
    local response = {}

    local username
    local usernames = {}
    local locked = {}
    local i

    status = true


    local result, hostinfo
    -- Initialize the hostinfo object, which sets up the initial variables
    result, hostinfo = initialize(host)
    if(result == false) then
        return false, hostinfo
    end
    

    -- If invalid accounts don't give guest, we can determine the existence of users by trying to 
    -- log in with an invalid password and checking the value
--     status, err = validate_usernames(hostinfo)
--     if(status == false) then
--         return false, err
--     end

    -- Start up the SMB session
    status, err = restart_session(hostinfo)
    if(status == false) then
        return false, err
    end

    -- Loop through the password list
    password = hostinfo['password_list']()
    username = hostinfo['user_list_default']()

    io.write(string.format("%s:%s\n", username, password))
    local result = check_login(hostinfo, username, password, get_type(hostinfo))

    -- Check if the username was locked out
    if(is_bad_result(hostinfo, result)) then
        -- Add it to the list of locked usernames
        hostinfo['locked_usernames'][username] = true

        -- Unless the user requested to keep going, stop the check
                    -- Mark it as found, which is technically true
        status, err = found_account(hostinfo, username, nil, results.ACCOUNT_LOCKED_NOW)
        if(status == false) then
            return err
        end

        -- Let the user know that it went badly
        stdnse.print_debug(1, "smb-brute: '%s' became locked out; stopping", username)

        return true, hostinfo['accounts'], hostinfo['locked_usernames']
    end

    if(is_positive_result(hostinfo, result)) then
        -- Reset the connection
        stdnse.print_debug(2, "smb-brute: Found an account; resetting connection")
        status, err = restart_session(hostinfo)
        if(status == false) then
            return false, err
        end

        -- Find the case of the password, unless it's a hash
        case_password = password

        -- Take normal actions for finding an account
        status, err = found_account(hostinfo, username, case_password, result)
        if(status == false) then
            return err
        end
    end

    stop_session(hostinfo)



    -- Do reporting

    table.insert(response, "No accounts found")
    return stdnse.format_output(true, response)
end
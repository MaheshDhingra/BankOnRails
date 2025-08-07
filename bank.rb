# bank.rb

require 'pg'
require 'bcrypt' # Added for password hashing
require 'date' # Added for date parsing in account statements

class Account
  attr_reader :account_id, :user_id, :account_type, :balance, :status, :overdraft_limit, :daily_withdrawal_limit, :daily_transfer_limit

  def initialize(account_id, user_id, account_type, balance, status, overdraft_limit, daily_withdrawal_limit, daily_transfer_limit, bank = nil)
    @account_id = account_id
    @user_id = user_id
    @account_type = account_type
    @balance = balance
    @status = status
    @overdraft_limit = overdraft_limit
    @daily_withdrawal_limit = daily_withdrawal_limit
    @daily_transfer_limit = daily_transfer_limit
    @bank = bank # Reference to the bank instance
  end

  def deposit(amount)
    if @status == 'frozen'
      puts "Account is frozen. Deposit not allowed."
      @bank.record_activity(@user_id, @account_id, 'deposit_failed', "Attempted deposit of #{amount} to frozen account.")
      return
    end

    if amount <= 0
      puts "Deposit amount must be positive."
      @bank.record_activity(@user_id, @account_id, 'deposit_failed', "Attempted deposit of non-positive amount #{amount}.")
      return
    end
    @balance += amount
    @bank.update_account_balance(@account_id, @balance) if @bank
    @bank.record_activity(@user_id, @account_id, 'deposit', "Deposited #{amount}. New balance: #{@balance}")
    puts "Deposited #{amount}. New balance: #{@balance}"
  end

  def withdraw(amount)
    if @status == 'frozen'
      puts "Account is frozen. Withdrawal not allowed."
      @bank.record_activity(@user_id, @account_id, 'withdrawal_failed', "Attempted withdrawal of #{amount} from frozen account.")
      return
    end

    if amount <= 0
      puts "Withdrawal amount must be positive."
      @bank.record_activity(@user_id, @account_id, 'withdrawal_failed', "Attempted withdrawal of non-positive amount #{amount}.")
      return
    end

    # Feature 7: Daily Withdrawal Limit
    if @daily_withdrawal_limit > 0 && (@bank.get_current_daily_withdrawal(@account_id) + amount) > @daily_withdrawal_limit
      puts "Withdrawal of #{amount} exceeds daily withdrawal limit of #{@daily_withdrawal_limit}. Current daily withdrawal: #{@bank.get_current_daily_withdrawal(@account_id)}"
      @bank.record_activity(@user_id, @account_id, 'withdrawal_failed', "Exceeded daily withdrawal limit with amount #{amount}.")
      return
    end

    # Feature 1: Minimum Balance for Checking Accounts (and overdraft check)
    if @account_type == 'checking' && (@balance - amount) < 50 && (@balance - amount).abs > @overdraft_limit
      puts "Withdrawal would put checking account below minimum balance of 50 and exceeds overdraft limit. Current balance: #{@balance}"
      @bank.record_activity(@user_id, @account_id, 'withdrawal_failed', "Attempted withdrawal below minimum balance/overdraft limit with amount #{amount}.")
      return
    end

    if @balance + @overdraft_limit >= amount # Allow withdrawal if within overdraft limit
      @balance -= amount
      @bank.update_account_balance(@account_id, @balance) if @bank
      @bank.update_current_daily_withdrawal(@account_id, @bank.get_current_daily_withdrawal(@account_id) + amount)
      @bank.record_activity(@user_id, @account_id, 'withdrawal', "Withdrew #{amount}. New balance: #{@balance}")
      puts "Withdrew #{amount}. New balance: #{@balance}"
    else
      puts "Insufficient funds. Current balance: #{@balance}. Overdraft limit: #{@overdraft_limit}"
      @bank.record_activity(@user_id, @account_id, 'withdrawal_failed', "Insufficient funds for withdrawal of #{amount}.")
    end
  end
end

class Bank
  def initialize
    @conn = PG.connect(ENV['DATABASE_URL'] || 'postgresql://neondb_owner:npg_kGSyVnKF8sL5@ep-bitter-pine-a1t8q2hc-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require')
    create_tables
  end

  def create_tables
    @conn.exec("CREATE TABLE IF NOT EXISTS users (
      user_id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL
    )")
    @conn.exec("CREATE TABLE IF NOT EXISTS accounts (
      account_id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(user_id),
      account_type VARCHAR(50) NOT NULL,
      balance DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      status VARCHAR(50) NOT NULL DEFAULT 'active',
      overdraft_limit DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      description VARCHAR(255),
      daily_withdrawal_limit DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      daily_transfer_limit DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      current_daily_withdrawal DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      current_daily_transfer DECIMAL(10, 2) NOT NULL DEFAULT 0.00
    )")
    @conn.exec("CREATE TABLE IF NOT EXISTS transactions (
      transaction_id SERIAL PRIMARY KEY,
      account_id INTEGER REFERENCES accounts(account_id),
      type VARCHAR(50) NOT NULL,
      amount DECIMAL(10, 2) NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )")
    @conn.exec("CREATE TABLE IF NOT EXISTS activity_log (
      log_id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(user_id),
      account_id INTEGER REFERENCES accounts(account_id),
      activity_type VARCHAR(255) NOT NULL,
      details TEXT,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )")
    @conn.exec("CREATE TABLE IF NOT EXISTS bills (
      bill_id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(user_id),
      payee VARCHAR(255) NOT NULL,
      amount DECIMAL(10, 2) NOT NULL,
      due_date DATE NOT NULL,
      status VARCHAR(50) NOT NULL DEFAULT 'pending'
    )")
  end

  def register_user(username, password)
    password_hash = BCrypt::Password.create(password)
    @conn.exec_params("INSERT INTO users (username, password_hash) VALUES ($1, $2)", [username, password_hash])
    puts "User '#{username}' registered successfully."
  rescue PG::UniqueViolation
    puts "Username '#{username}' already exists. Please choose a different one."
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def login_user(username, password)
    result = @conn.exec_params("SELECT user_id, password_hash FROM users WHERE username = $1", [username])
    if result.any?
      user_data = result[0]
      if BCrypt::Password.new(user_data['password_hash']) == password
        puts "Login successful for '#{username}'."
        return user_data['user_id']
      else
        puts "Incorrect password."
      end
    else
      puts "User '#{username}' not found."
    end
    nil
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    nil
  end

  def create_account(user_id, account_type, initial_balance)
    @conn.exec_params("INSERT INTO accounts (user_id, account_type, balance) VALUES ($1, $2, $3) RETURNING account_id", [user_id, account_type, initial_balance])
    puts "#{account_type.capitalize} account created with initial balance of #{initial_balance} for user ID #{user_id}."
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def get_account(account_id)
    result = @conn.exec_params("SELECT account_id, user_id, account_type, balance, status, overdraft_limit, daily_withdrawal_limit, daily_transfer_limit, current_daily_withdrawal, current_daily_transfer FROM accounts WHERE account_id = $1", [account_id])
    if result.any?
      data = result[0]
      Account.new(data['account_id'], data['user_id'], data['account_type'], data['balance'].to_f, data['status'], data['overdraft_limit'].to_f, data['daily_withdrawal_limit'].to_f, data['daily_transfer_limit'].to_f, self)
    else
      nil
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    nil
  end

  def get_user_accounts(user_id)
    result = @conn.exec_params("SELECT account_id, user_id, account_type, balance, status, overdraft_limit, daily_withdrawal_limit, daily_transfer_limit, current_daily_withdrawal, current_daily_transfer FROM accounts WHERE user_id = $1", [user_id])
    accounts = []
    result.each do |data|
      accounts << Account.new(data['account_id'], data['user_id'], data['account_type'], data['balance'].to_f, data['status'], data['overdraft_limit'].to_f, data['daily_withdrawal_limit'].to_f, data['daily_transfer_limit'].to_f, self)
    end
    accounts
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    []
  end

  def display_all_accounts
    result = @conn.exec("SELECT u.username, a.account_id, a.account_type, a.balance FROM accounts a JOIN users u ON a.user_id = u.user_id")
    if result.empty?
      puts "No accounts in the bank."
    else
      puts "\n--- All Accounts ---"
      result.each do |row|
        puts "User: #{row['username']}, Account ID: #{row['account_id']}, Type: #{row['account_type']}, Balance: #{row['balance']}"
      end
      puts "--------------------"
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def update_account_balance(account_id, new_balance)
    @conn.exec_params("UPDATE accounts SET balance = $1 WHERE account_id = $2", [new_balance, account_id])
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def record_transaction(account_id, type, amount)
    @conn.exec_params("INSERT INTO transactions (account_id, type, amount) VALUES ($1, $2, $3)", [account_id, type, amount])
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def record_activity(user_id, account_id, activity_type, details) # Feature 6: Activity Logging
    @conn.exec_params("INSERT INTO activity_log (user_id, account_id, activity_type, details) VALUES ($1, $2, $3, $4)", [user_id, account_id, activity_type, details])
  rescue PG::Error => e
    puts "Database error recording activity: #{e.message}"
  end

  def get_current_daily_withdrawal(account_id)
    result = @conn.exec_params("SELECT current_daily_withdrawal FROM accounts WHERE account_id = $1", [account_id])
    result[0]['current_daily_withdrawal'].to_f
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    0.0
  end

  def update_current_daily_withdrawal(account_id, amount)
    @conn.exec_params("UPDATE accounts SET current_daily_withdrawal = $1 WHERE account_id = $2", [amount, account_id])
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def get_current_daily_transfer(account_id)
    result = @conn.exec_params("SELECT current_daily_transfer FROM accounts WHERE account_id = $1", [account_id])
    result[0]['current_daily_transfer'].to_f
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    0.0
  end

  def update_current_daily_transfer(account_id, amount)
    @conn.exec_params("UPDATE accounts SET current_daily_transfer = $1 WHERE account_id = $2", [amount, account_id])
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def reset_daily_limits_for_all_accounts # Admin feature to reset daily limits
    @conn.exec("UPDATE accounts SET current_daily_withdrawal = 0, current_daily_transfer = 0")
    puts "Daily withdrawal and transfer limits reset for all accounts."
    record_activity(nil, nil, 'admin_action', 'Daily limits reset for all accounts.')
  rescue PG::Error => e
    puts "Database error resetting daily limits: #{e.message}"
  end

  def get_transaction_history(account_id, type_filter = nil) # Feature 5: Search Transactions by Type
    query = "SELECT type, amount, timestamp FROM transactions WHERE account_id = $1"
    params = [account_id]

    if type_filter && !type_filter.empty?
      query += " AND type = $2"
      params << type_filter
    end
    query += " ORDER BY timestamp DESC"

    result = @conn.exec_params(query, params)
    if result.empty?
      puts "No transactions found for account ID #{account_id}#{" with type '#{type_filter}'" if type_filter}."
    else
      puts "\n--- Transaction History for Account ID #{account_id}#{" (Type: #{type_filter})" if type_filter} ---"
      result.each do |row|
        puts "Type: #{row['type']}, Amount: #{row['amount']}, Date: #{row['timestamp']}"
      end
      puts "------------------------------------------"
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def generate_account_statement(account_id, start_date_str, end_date_str)
    begin
      start_date = Date.parse(start_date_str)
      end_date = Date.parse(end_date_str)
    rescue ArgumentError
      puts "Invalid date format. Please use YYYY-MM-DD."
      return
    end

    result = @conn.exec_params("SELECT type, amount, timestamp FROM transactions WHERE account_id = $1 AND timestamp BETWEEN $2 AND $3 ORDER BY timestamp ASC", [account_id, start_date.to_s, end_date.to_s])

    if result.empty?
      puts "No transactions found for account ID #{account_id} between #{start_date_str} and #{end_date_str}."
    else
      puts "\n--- Account Statement for Account ID #{account_id} (#{start_date_str} to #{end_date_str}) ---"
      result.each do |row|
        puts "Type: #{row['type']}, Amount: #{row['amount']}, Date: #{row['timestamp']}"
      end
      puts "-----------------------------------------------------------------"
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def set_account_status(account_id, status)
    unless ['frozen', 'active'].include?(status)
      puts "Invalid status. Must be 'frozen' or 'active'."
      return
    end
    @conn.exec_params("UPDATE accounts SET status = $1 WHERE account_id = $2", [status, account_id])
    puts "Account ID #{account_id} set to #{status}."
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def set_overdraft_limit(account_id, limit)
    if limit < 0
      puts "Overdraft limit cannot be negative."
      return
    end
    @conn.exec_params("UPDATE accounts SET overdraft_limit = $1 WHERE account_id = $2", [limit, account_id])
    puts "Overdraft limit for account ID #{account_id} set to #{limit}."
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def change_user_password(user_id, current_password, new_password)
    result = @conn.exec_params("SELECT password_hash FROM users WHERE user_id = $1", [user_id])
    if result.any?
      user_data = result[0]
      if BCrypt::Password.new(user_data['password_hash']) == current_password
        new_password_hash = BCrypt::Password.create(new_password)
        @conn.exec_params("UPDATE users SET password_hash = $1 WHERE user_id = $2", [new_password_hash, user_id])
        puts "Password changed successfully."
      else
        puts "Incorrect current password."
      end
    else
      puts "User not found."
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def view_account_summary(user_id) # New Feature 5
    accounts = get_user_accounts(user_id)
    if accounts.empty?
      puts "You have no accounts to display a summary for."
    else
      puts "\n--- Your Account Summary ---"
      accounts.each do |acc|
        puts "Account ID: #{acc.account_id}, Type: #{acc.account_type}, Balance: #{acc.balance}"
      end
      puts "----------------------------"
    end
  end

  def generate_account_statement(account_id, start_date_str, end_date_str)
    begin
      start_date = Date.parse(start_date_str)
      end_date = Date.parse(end_date_str)
    rescue ArgumentError
      puts "Invalid date format. Please use YYYY-MM-DD."
      return
    end

    result = @conn.exec_params("SELECT type, amount, timestamp FROM transactions WHERE account_id = $1 AND timestamp BETWEEN $2 AND $3 ORDER BY timestamp ASC", [account_id, start_date.to_s, end_date.to_s])

    if result.empty?
      puts "No transactions found for account ID #{account_id} between #{start_date_str} and #{end_date_str}."
    else
      puts "\n--- Account Statement for Account ID #{account_id} (#{start_date_str} to #{end_date_str}) ---"
      result.each do |row|
        puts "Type: #{row['type']}, Amount: #{row['amount']}, Date: #{row['timestamp']}"
      end
      puts "-----------------------------------------------------------------"
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def transfer_funds(from_account_id, to_account_id, amount)
    from_account = get_account(from_account_id)
    to_account = get_account(to_account_id)

    if amount <= 0
      puts "Transfer amount must be positive."
      return
    end

    if from_account && to_account
      if from_account.status == 'frozen'
        puts "Source account #{from_account_id} is frozen. Transfer not allowed."
        record_activity(from_account.user_id, from_account_id, 'transfer_failed', "Attempted transfer from frozen account #{from_account_id}.")
        return
      end
      if to_account.status == 'frozen'
        puts "Destination account #{to_account_id} is frozen. Transfer not allowed."
        record_activity(to_account.user_id, to_account_id, 'transfer_failed', "Attempted transfer to frozen account #{to_account_id}.")
        return
      end

      # Feature 7: Daily Transfer Limit
      if from_account.daily_transfer_limit > 0 && (@conn.get_current_daily_transfer(from_account_id) + amount) > from_account.daily_transfer_limit
        puts "Transfer of #{amount} exceeds daily transfer limit of #{from_account.daily_transfer_limit} for account #{from_account_id}. Current daily transfer: #{@conn.get_current_daily_transfer(from_account_id)}"
        record_activity(from_account.user_id, from_account_id, 'transfer_failed', "Exceeded daily transfer limit with amount #{amount}.")
        return
      end

      if from_account.balance + from_account.overdraft_limit >= amount
        @conn.transaction do |conn|
          conn.exec_params("UPDATE accounts SET balance = balance - $1 WHERE account_id = $2", [amount, from_account_id])
          conn.exec_params("UPDATE accounts SET balance = balance + $1 WHERE account_id = $2", [amount, to_account_id])
          record_transaction(from_account_id, 'transfer_out', amount)
          record_transaction(to_account_id, 'transfer_in', amount)
          update_current_daily_transfer(from_account_id, get_current_daily_transfer(from_account_id) + amount)
        end
        puts "Transferred #{amount} from account #{from_account_id} to account #{to_account_id}."
        record_activity(from_account.user_id, from_account_id, 'transfer_successful', "Transferred #{amount} to account #{to_account_id}.")
        record_activity(to_account.user_id, to_account_id, 'transfer_received', "Received #{amount} from account #{from_account_id}.")
      else
        puts "Insufficient funds in account #{from_account_id} for transfer. Current balance: #{from_account.balance}, Overdraft limit: #{from_account.overdraft_limit}"
        record_activity(from_account.user_id, from_account_id, 'transfer_failed', "Insufficient funds for transfer of #{amount}.")
      end
    else
      puts "One or both accounts not found for transfer."
      record_activity(nil, from_account_id, 'transfer_failed', "Transfer attempt with invalid account IDs: from #{from_account_id} to #{to_account_id}.")
    end
  rescue PG::Error => e
    puts "Database error during transfer: #{e.message}"
    @conn.rollback if @conn.transaction_status == PG::PQTRANS_INTRANS
    record_activity(nil, nil, 'transfer_failed', "Database error during transfer: #{e.message}")
  end

  def calculate_interest(account_id, rate_percentage)
    account = get_account(account_id)
    if account && account.account_type == 'savings'
      if account.status == 'frozen'
        puts "Account is frozen. Interest calculation not allowed."
        record_activity(account.user_id, account_id, 'interest_failed', "Attempted interest calculation on frozen account.")
        return
      end
      interest = account.balance * (rate_percentage / 100.0)
      new_balance = account.balance + interest
      update_account_balance(account_id, new_balance)
      record_transaction(account_id, 'interest_earned', interest)
      record_activity(account.user_id, account_id, 'interest_calculated', "Interest of #{interest} calculated. New balance: #{new_balance}")
      puts "Interest of #{interest} calculated and added to account #{account_id}. New balance: #{new_balance}"
    elsif account
      puts "Interest can only be calculated for savings accounts."
      record_activity(account.user_id, account_id, 'interest_failed', "Attempted interest calculation on non-savings account.")
    else
      puts "Account not found."
      record_activity(nil, account_id, 'interest_failed', "Attempted interest calculation on non-existent account.")
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    record_activity(nil, account_id, 'interest_failed', "Database error during interest calculation: #{e.message}")
  end

  def apply_for_loan(user_id, loan_amount)
    if loan_amount <= 0
      puts "Loan amount must be positive."
      record_activity(user_id, nil, 'loan_application_failed', "Attempted loan application with non-positive amount #{loan_amount}.")
      return
    end

    # Feature 8: Loan Eligibility Check (basic)
    user_accounts = get_user_accounts(user_id)
    total_balance = user_accounts.sum(&:balance)
    if total_balance < loan_amount * 0.1 # Example: user must have at least 10% of loan amount in other accounts
      puts "Loan application denied. Total balance across your accounts is too low for a loan of #{loan_amount}. You need at least #{loan_amount * 0.1}."
      record_activity(user_id, nil, 'loan_application_denied', "Loan amount #{loan_amount} denied due to low total balance.")
      return
    end

    puts "Loan application for #{loan_amount} for user ID #{user_id} submitted."
    # For simplicity, let's auto-approve and create a loan account or add to an existing one
    # In a real system, this would be more complex, involving a separate loans table
    create_account(user_id, 'loan', loan_amount)
    record_activity(user_id, nil, 'loan_approved', "Loan of #{loan_amount} approved.")
    puts "Loan of #{loan_amount} approved and added to a new loan account for user ID #{user_id}."
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    record_activity(user_id, nil, 'loan_application_failed', "Database error during loan application: #{e.message}")
  end

  def repay_loan(account_id, amount)
    account = get_account(account_id)
    if amount <= 0
      puts "Repayment amount must be positive."
      record_activity(account.user_id, account_id, 'loan_repayment_failed', "Attempted repayment of non-positive amount #{amount}.")
      return
    end

    if account && account.account_type == 'loan'
      if account.status == 'frozen'
        puts "Account is frozen. Loan repayment not allowed."
        record_activity(account.user_id, account_id, 'loan_repayment_failed', "Attempted repayment on frozen loan account.")
        return
      end
      # Assuming loan balance is positive for outstanding amount, so repayment reduces it
      if account.balance >= amount
        new_balance = account.balance - amount
        update_account_balance(account_id, new_balance)
        record_transaction(account_id, 'loan_repayment', amount)
        record_activity(account.user_id, account_id, 'loan_repayment', "Repaid #{amount} on loan account #{account_id}. Remaining balance: #{new_balance}")
        puts "Repaid #{amount} on loan account #{account_id}. Remaining balance: #{new_balance}"
      else
        puts "Amount to repay exceeds outstanding loan balance. Outstanding: #{account.balance}"
        record_activity(account.user_id, account_id, 'loan_repayment_failed', "Repayment amount #{amount} exceeds outstanding loan balance.")
      end
    elsif account
      puts "This is not a loan account."
      record_activity(account.user_id, account_id, 'loan_repayment_failed', "Attempted repayment on non-loan account.")
    else
      puts "Account not found."
      record_activity(nil, account_id, 'loan_repayment_failed', "Attempted repayment on non-existent account.")
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    record_activity(nil, account_id, 'loan_repayment_failed', "Database error during loan repayment: #{e.message}")
  end

  def delete_account(account_id)
    account = get_account(account_id)
    if account
      if account.balance != 0 # Feature 10: Prevent Deletion of Non-Zero Balance Accounts
        puts "Account ID #{account_id} cannot be deleted because its balance is not zero. Current balance: #{account.balance}"
        record_activity(account.user_id, account_id, 'account_deletion_failed', "Attempted to delete non-zero balance account.")
        return
      end

      print "Are you sure you want to delete account ID #{account_id}? (yes/no): "
      confirmation = gets.chomp.downcase
      if confirmation == 'yes'
        @conn.exec_params("DELETE FROM transactions WHERE account_id = $1", [account_id])
        @conn.exec_params("DELETE FROM accounts WHERE account_id = $1", [account_id])
        record_activity(account.user_id, account_id, 'account_deleted', "Account ID #{account_id} and its transactions deleted.")
        puts "Account ID #{account_id} and its transactions deleted."
      else
        puts "Account deletion cancelled."
        record_activity(account.user_id, account_id, 'account_deletion_cancelled', "Account deletion cancelled by user.")
      end
    else
      puts "Account not found."
      record_activity(nil, account_id, 'account_deletion_failed', "Attempted to delete non-existent account.")
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    record_activity(nil, account_id, 'account_deletion_failed', "Database error during account deletion: #{e.message}")
  end

  def delete_user(user_id)
    # Feature 10: Prevent Deletion of Non-Zero Balance Accounts (for user's accounts)
    user_accounts = get_user_accounts(user_id)
    if user_accounts.any? { |acc| acc.balance != 0 }
      puts "Cannot delete user ID #{user_id}. One or more associated accounts have a non-zero balance."
      record_activity(user_id, nil, 'user_deletion_failed', "Attempted to delete user with non-zero balance accounts.")
      return
    end

    # First delete all accounts and their transactions for the user
    user_accounts.each do |account|
      # Directly delete without confirmation prompt here to avoid nested prompts
      @conn.exec_params("DELETE FROM transactions WHERE account_id = $1", [account.account_id])
      @conn.exec_params("DELETE FROM accounts WHERE account_id = $1", [account.account_id])
      record_activity(user_id, account.account_id, 'account_deleted_by_user_deletion', "Account ID #{account.account_id} deleted as part of user deletion.")
      puts "Account ID #{account.account_id} deleted as part of user deletion."
    end
    @conn.exec_params("DELETE FROM users WHERE user_id = $1", [user_id])
    record_activity(user_id, nil, 'user_deleted', "User ID #{user_id} and all associated accounts deleted.")
    puts "User ID #{user_id} and all associated accounts deleted."
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    record_activity(user_id, nil, 'user_deletion_failed', "Database error during user deletion: #{e.message}")
  end

  def get_user_details(user_id) # Feature 3: Admin - View User Details
    user_result = @conn.exec_params("SELECT username FROM users WHERE user_id = $1", [user_id])
    if user_result.any?
      username = user_result[0]['username']
      puts "\n--- User Details for User ID: #{user_id} (Username: #{username}) ---"
      accounts = get_user_accounts(user_id)
      if accounts.empty?
        puts "No accounts associated with this user."
      else
        puts "Associated Accounts:"
        accounts.each do |acc|
          puts "  Account ID: #{acc.account_id}, Type: #{acc.account_type}, Balance: #{acc.balance}, Status: #{acc.status}, Overdraft Limit: #{acc.overdraft_limit}, Daily Withdrawal Limit: #{acc.daily_withdrawal_limit}, Daily Transfer Limit: #{acc.daily_transfer_limit}"
        end
      end
      puts "-------------------------------------------------"
      record_activity(nil, nil, 'admin_view_user_details', "Viewed details for user ID #{user_id}.")
    else
      puts "User ID #{user_id} not found."
      record_activity(nil, nil, 'admin_view_user_details_failed', "Attempted to view details for non-existent user ID #{user_id}.")
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    record_activity(nil, nil, 'admin_view_user_details_failed', "Database error viewing user details: #{e.message}")
  end

  def set_account_description(account_id, description) # Feature 4: Account Nickname/Description
    @conn.exec_params("UPDATE accounts SET description = $1 WHERE account_id = $2", [description, account_id])
    puts "Description for account ID #{account_id} set to: '#{description}'."
    record_activity(nil, account_id, 'account_description_set', "Description for account ID #{account_id} set to '#{description}'.")
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    record_activity(nil, account_id, 'account_description_failed', "Database error setting account description: #{e.message}")
  end

  def schedule_bill(user_id, payee, amount, due_date_str) # Feature 9: Bill Payment Scheduling
    begin
      due_date = Date.parse(due_date_str)
    rescue ArgumentError
      puts "Invalid date format for due date. Please use YYYY-MM-DD."
      record_activity(user_id, nil, 'schedule_bill_failed', "Invalid due date format: #{due_date_str}.")
      return
    end

    if amount <= 0
      puts "Bill amount must be positive."
      record_activity(user_id, nil, 'schedule_bill_failed', "Attempted to schedule bill with non-positive amount #{amount}.")
      return
    end

    @conn.exec_params("INSERT INTO bills (user_id, payee, amount, due_date, status) VALUES ($1, $2, $3, $4, 'pending')", [user_id, payee, amount, due_date.to_s])
    puts "Bill for #{payee} of #{amount} due on #{due_date_str} scheduled successfully."
    record_activity(user_id, nil, 'bill_scheduled', "Bill for #{payee} of #{amount} due on #{due_date_str} scheduled.")
  rescue PG::Error => e
    puts "Database error scheduling bill: #{e.message}"
    record_activity(user_id, nil, 'schedule_bill_failed', "Database error scheduling bill: #{e.message}")
  end

  def pay_bill(bill_id, account_id) # Feature 9: Pay Scheduled Bill
    bill_result = @conn.exec_params("SELECT user_id, payee, amount, status FROM bills WHERE bill_id = $1", [bill_id])
    if bill_result.empty?
      puts "Bill ID #{bill_id} not found."
      record_activity(nil, nil, 'pay_bill_failed', "Attempted to pay non-existent bill ID #{bill_id}.")
      return
    end

    bill_data = bill_result[0]
    user_id = bill_data['user_id']
    payee = bill_data['payee']
    amount = bill_data['amount'].to_f
    status = bill_data['status']

    if status == 'paid'
      puts "Bill ID #{bill_id} has already been paid."
      record_activity(user_id, bill_id, 'pay_bill_failed', "Attempted to pay already paid bill ID #{bill_id}.")
      return
    end

    account = get_account(account_id)
    if account && account.user_id == user_id
      if account.status == 'frozen'
        puts "Account is frozen. Cannot pay bill."
        record_activity(user_id, account_id, 'pay_bill_failed', "Attempted to pay bill from frozen account.")
        return
      end

      if account.balance >= amount
        @conn.transaction do |conn|
          conn.exec_params("UPDATE accounts SET balance = balance - $1 WHERE account_id = $2", [amount, account_id])
          conn.exec_params("UPDATE bills SET status = 'paid' WHERE bill_id = $1", [bill_id])
          record_transaction(account_id, 'bill_payment', amount)
        end
        puts "Bill ID #{bill_id} for #{payee} paid successfully from account #{account_id}. Amount: #{amount}"
        record_activity(user_id, account_id, 'bill_paid', "Bill ID #{bill_id} for #{payee} paid from account #{account_id}.")
      else
        puts "Insufficient funds in account #{account_id} to pay bill. Current balance: #{account.balance}"
        record_activity(user_id, account_id, 'pay_bill_failed', "Insufficient funds to pay bill ID #{bill_id}.")
      end
    else
      puts "Account not found or does not belong to the bill's user."
      record_activity(user_id, account_id, 'pay_bill_failed', "Account not found or mismatch for bill ID #{bill_id}.")
    end
  rescue PG::Error => e
    puts "Database error paying bill: #{e.message}"
    @conn.rollback if @conn.transaction_status == PG::PQTRANS_INTRANS
    record_activity(user_id, nil, 'pay_bill_failed', "Database error paying bill: #{e.message}")
  end

  def view_scheduled_bills(user_id) # Feature 9: View Scheduled Bills
    result = @conn.exec_params("SELECT bill_id, payee, amount, due_date, status FROM bills WHERE user_id = $1 ORDER BY due_date ASC", [user_id])
    if result.empty?
      puts "No scheduled bills found for user ID #{user_id}."
    else
      puts "\n--- Your Scheduled Bills ---"
      result.each do |row|
        puts "Bill ID: #{row['bill_id']}, Payee: #{row['payee']}, Amount: #{row['amount']}, Due Date: #{row['due_date']}, Status: #{row['status']}"
      end
      puts "----------------------------"
    end
  rescue PG::Error => e
    puts "Database error viewing scheduled bills: #{e.message}"
  end

  def view_activity_log(user_id = nil) # Feature 6: View Activity Log (Admin or User specific)
    query = "SELECT user_id, account_id, activity_type, details, timestamp FROM activity_log"
    params = []
    if user_id
      query += " WHERE user_id = $1"
      params << user_id
    end
    query += " ORDER BY timestamp DESC"

    result = @conn.exec_params(query, params)
    if result.empty?
      puts "No activity found#{" for user ID #{user_id}" if user_id}."
    else
      puts "\n--- Activity Log#{" for User ID #{user_id}" if user_id} ---"
      result.each do |row|
        puts "User ID: #{row['user_id'] || 'N/A'}, Account ID: #{row['account_id'] || 'N/A'}, Type: #{row['activity_type']}, Details: #{row['details']}, Time: #{row['timestamp']}"
      end
      puts "-------------------------------------------------"
    end
  rescue PG::Error => e
    puts "Database error viewing activity log: #{e.message}"
  end
end

  def get_user_details(user_id) # Feature 3: Admin - View User Details
    user_result = @conn.exec_params("SELECT username FROM users WHERE user_id = $1", [user_id])
    if user_result.any?
      username = user_result[0]['username']
      puts "\n--- User Details for User ID: #{user_id} (Username: #{username}) ---"
      accounts = get_user_accounts(user_id)
      if accounts.empty?
        puts "No accounts associated with this user."
      else
        puts "Associated Accounts:"
        accounts.each do |acc|
          puts "  Account ID: #{acc.account_id}, Type: #{acc.account_type}, Balance: #{acc.balance}, Status: #{acc.status}, Overdraft Limit: #{acc.overdraft_limit}"
        end
      end
      puts "-------------------------------------------------"
    else
      puts "User ID #{user_id} not found."
    end
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end

  def set_account_description(account_id, description) # Feature 4: Account Nickname/Description
    @conn.exec_params("UPDATE accounts SET description = $1 WHERE account_id = $2", [description, account_id])
    puts "Description for account ID #{account_id} set to: '#{description}'."
  rescue PG::Error => e
    puts "Database error: #{e.message}"
  end
end

def run_bank_app
  bank = Bank.new
  puts "Welcome to the Ruby Terminal Bank!"
  current_user_id = nil

  loop do
    unless current_user_id
      puts "\n--- Authentication ---"
      puts "1. Register"
      puts "2. Login"
      puts "3. Exit"
      print "Enter your choice: "
      auth_choice = gets.chomp.to_i

      case auth_choice
      when 1
        print "Enter desired username: "
        username = gets.chomp
        print "Enter password: "
        password = gets.chomp
        bank.register_user(username, password)
      when 2
        print "Enter username: "
        username = gets.chomp
        print "Enter password: "
        password = gets.chomp
        current_user_id = bank.login_user(username, password)
      when 3
        puts "Thank you for using the Ruby Terminal Bank. Goodbye!"
        break
      else
        puts "Invalid choice. Please try again."
      end
    else
      puts "\n--- Main Menu (Logged in as User ID: #{current_user_id}) ---"
      puts "1. Create Account"
      puts "2. Deposit Funds"
      puts "3. Withdraw Funds"
      puts "4. Transfer Funds"
      puts "5. View Account Balance"
      puts "6. View Transaction History"
      puts "7. List My Accounts"
      puts "8. Calculate Interest (Savings Accounts)"
      puts "9. Apply for Loan"
      puts "10. Repay Loan"
      puts "11. Delete Account"
      puts "12. Delete My User Account"
      puts "13. Logout"
      puts "14. Admin: List All Accounts (All Users)"
      puts "15. Generate Account Statement" # New Feature 1
      puts "16. Admin: Freeze/Unfreeze Account" # New Feature 2
      puts "17. Admin: Set Account Overdraft Limit" # New Feature 3
      puts "18. Change Password" # New Feature 4
      puts "19. View Account Summary"
      puts "20. Admin: View User Details"
      puts "21. Set Account Description"
      puts "22. Schedule Bill Payment" # New Feature 9
      puts "23. Pay Scheduled Bill" # New Feature 9
      puts "24. View Scheduled Bills" # New Feature 9
      puts "25. View My Activity Log" # New Feature 6
      puts "26. Admin: View All Activity Log" # New Feature 6
      puts "27. Admin: Set Daily Withdrawal Limit" # New Feature 7
      puts "28. Admin: Set Daily Transfer Limit" # New Feature 7
      puts "29. Admin: Reset All Daily Limits" # New Feature 7
      puts "30. Exit"
      print "Enter your choice: "
      choice = gets.chomp.to_i

      case choice
      when 1
        print "Enter account type (checking/savings/loan): "
        account_type = gets.chomp.downcase
        print "Enter initial balance: "
        initial_balance = gets.chomp.to_f
        bank.create_account(current_user_id, account_type, initial_balance)
      when 2
        print "Enter account ID to deposit into: "
        account_id = gets.chomp.to_i
        account = bank.get_account(account_id)
        if account && account.user_id == current_user_id
          print "Enter amount to deposit: "
          amount = gets.chomp.to_f
          account.deposit(amount)
          bank.record_transaction(account_id, 'deposit', amount)
        else
          puts "Account not found or does not belong to you."
        end
      when 3
        print "Enter account ID to withdraw from: "
        account_id = gets.chomp.to_i
        account = bank.get_account(account_id)
        if account && account.user_id == current_user_id
          print "Enter amount to withdraw: "
          amount = gets.chomp.to_f
          account.withdraw(amount)
          bank.record_transaction(account_id, 'withdraw', amount)
        else
          puts "Account not found or does not belong to you."
        end
      when 4
        print "Enter your account ID (from): "
        from_account_id = gets.chomp.to_i
        print "Enter recipient's account ID (to): "
        to_account_id = gets.chomp.to_i
        print "Enter amount to transfer: "
        amount = gets.chomp.to_f
        bank.transfer_funds(from_account_id, to_account_id, amount)
      when 5
        print "Enter account ID to check balance: "
        account_id = gets.chomp.to_i
        account = bank.get_account(account_id)
        if account && account.user_id == current_user_id
          puts "Account ID: #{account.account_id}, Type: #{account.account_type}, Balance: #{account.balance}"
        else
          puts "Account not found or does not belong to you."
        end
      when 6
        print "Enter account ID to view transaction history: "
        account_id = gets.chomp.to_i
        account = bank.get_account(account_id)
        if account && account.user_id == current_user_id
          bank.get_transaction_history(account_id)
        else
          puts "Account not found or does not belong to you."
        end
      when 7
        my_accounts = bank.get_user_accounts(current_user_id)
        if my_accounts.empty?
          puts "You have no accounts."
        else
          puts "\n--- Your Accounts ---"
          my_accounts.each do |acc|
            puts "Account ID: #{acc.account_id}, Type: #{acc.account_type}, Balance: #{acc.balance}"
          end
          puts "---------------------"
        end
      when 8
        print "Enter savings account ID to calculate interest: "
        account_id = gets.chomp.to_i
        print "Enter interest rate percentage (e.g., 2.5 for 2.5%): "
        rate = gets.chomp.to_f
        bank.calculate_interest(account_id, rate)
      when 9
        print "Enter loan amount: "
        loan_amount = gets.chomp.to_f
        bank.apply_for_loan(current_user_id, loan_amount)
      when 10
        print "Enter loan account ID to repay: "
        account_id = gets.chomp.to_i
        print "Enter amount to repay: "
        amount = gets.chomp.to_f
        bank.repay_loan(account_id, amount)
      when 11
        print "Enter account ID to delete: "
        account_id = gets.chomp.to_i
        account = bank.get_account(account_id)
        if account && account.user_id == current_user_id
          bank.delete_account(account_id)
        else
          puts "Account not found or does not belong to you."
        end
      when 12
        print "Are you sure you want to delete your user account and all associated accounts? (yes/no): "
        confirmation = gets.chomp.downcase
        if confirmation == 'yes'
          bank.delete_user(current_user_id)
          current_user_id = nil # Log out after deleting user
        else
          puts "User account deletion cancelled."
        end
      when 13
        current_user_id = nil
        puts "Logged out successfully."
      when 14
        # This is an admin-like feature, for demonstration purposes
        bank.display_all_accounts
      when 15 # New Feature 1: Generate Account Statement
        print "Enter account ID to generate statement for: "
        account_id = gets.chomp.to_i
        print "Enter start date (YYYY-MM-DD): "
        start_date_str = gets.chomp
        print "Enter end date (YYYY-MM-DD): "
        end_date_str = gets.chomp
        bank.generate_account_statement(account_id, start_date_str, end_date_str)
      when 16 # New Feature 2: Admin - Freeze/Unfreeze Account
        print "Enter account ID to freeze/unfreeze: "
        account_id = gets.chomp.to_i
        print "Enter status (frozen/active): "
        status = gets.chomp.downcase
        bank.set_account_status(account_id, status)
      when 17 # New Feature 3: Admin - Set Account Overdraft Limit
        print "Enter account ID to set overdraft limit for: "
        account_id = gets.chomp.to_i
        print "Enter overdraft limit amount: "
        limit = gets.chomp.to_f
        bank.set_overdraft_limit(account_id, limit)
      when 18 # New Feature 4: Change Password
        print "Enter your current password: "
        current_password = gets.chomp
        print "Enter your new password: "
        new_password = gets.chomp
        bank.change_user_password(current_user_id, current_password, new_password)
      when 19 # View Account Summary
        bank.view_account_summary(current_user_id)
      when 20 # Feature 3: Admin - View User Details
        print "Enter User ID to view details: "
        user_id_to_view = gets.chomp.to_i
        bank.get_user_details(user_id_to_view)
      when 21 # Set Account Description
        print "Enter account ID to set description for: "
        account_id = gets.chomp.to_i
        account = bank.get_account(account_id)
        if account && account.user_id == current_user_id
          print "Enter new description: "
          description = gets.chomp
          bank.set_account_description(account_id, description)
        else
          puts "Account not found or does not belong to you."
        end
      when 22 # Feature 9: Schedule Bill Payment
        print "Enter payee name: "
        payee = gets.chomp
        print "Enter amount: "
        amount = gets.chomp.to_f
        print "Enter due date (YYYY-MM-DD): "
        due_date_str = gets.chomp
        bank.schedule_bill(current_user_id, payee, amount, due_date_str)
      when 23 # Feature 9: Pay Scheduled Bill
        print "Enter bill ID to pay: "
        bill_id = gets.chomp.to_i
        print "Enter account ID to pay from: "
        account_id = gets.chomp.to_i
        bank.pay_bill(bill_id, account_id)
      when 24 # Feature 9: View Scheduled Bills
        bank.view_scheduled_bills(current_user_id)
      when 25 # Feature 6: View My Activity Log
        bank.view_activity_log(current_user_id)
      when 26 # Feature 6: Admin - View All Activity Log
        bank.view_activity_log # No user_id means all logs
      when 27 # Feature 7: Admin - Set Daily Withdrawal Limit
        print "Enter account ID to set daily withdrawal limit for: "
        account_id = gets.chomp.to_i
        print "Enter new daily withdrawal limit: "
        limit = gets.chomp.to_f
        bank.set_daily_withdrawal_limit(account_id, limit)
      when 28 # Feature 7: Admin - Set Daily Transfer Limit
        print "Enter account ID to set daily transfer limit for: "
        account_id = gets.chomp.to_i
        print "Enter new daily transfer limit: "
        limit = gets.chomp.to_f
        bank.set_daily_transfer_limit(account_id, limit)
      when 29 # Feature 7: Admin - Reset All Daily Limits
        bank.reset_daily_limits_for_all_accounts
      when 30
        puts "Thank you for using the Ruby Terminal Bank. Goodbye!"
        break
      else
        puts "Invalid choice. Please try again."
      end
    end
  end
end

run_bank_app

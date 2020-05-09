"""Created by Joe Awad

Generate a csv of iam users with active access key or password and flags if
the user doesn't meet security standards.
"""
import boto3
import pandas

ALL_USERS_CSV = "all_users.csv"
ACTIVE_USERS_CSV = "active_users.csv"
ACTIVE_USERS_ALL_COLUMNS_CSV = "active_users_all_columns.csv"

ACCESS_KEY_EXPIRATION_DAYS = 365

COLUMNS_TO_REMOVE = [
    "arn",
    "user_creation_time",
    "password_last_used",
    "password_last_changed",
    "password_next_rotation",
    "mfa_active",
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_1_last_used_date",
    "access_key_1_last_used_region",
    "access_key_1_last_used_service",
    "access_key_2_active",
    "access_key_2_last_rotated",
    "access_key_2_last_used_date",
    "access_key_2_last_used_region",
    "access_key_2_last_used_service",
    "cert_1_active",
    "cert_1_last_rotated",
    "cert_2_active",
    "cert_2_last_rotated"
]

CREDENTIAL_CHECKS = [
    {
        "column_name": "unused_password",
        "enabled": "password_enabled",
        "last_used": "password_last_used"
    },
    {
        "column_name": "unused_access_key_1",
        "enabled": "access_key_1_active",
        "last_used": "access_key_1_last_used_date"
    },
    {
        "column_name": "unused_access_key_2",
        "enabled": "access_key_2_active",
        "last_used": "access_key_2_last_used_date"
    }
]

def get_all_users():
    """Generates credential report from IAM and writes to ALL_USERS_CSV"""
    client = boto3.client("iam")

    client.generate_credential_report()
    response = client.get_credential_report()
    with open(ALL_USERS_CSV, "wb+") as f:
        f.write(response["Content"])
    print("{} created".format(ALL_USERS_CSV))

# Pandas filter functions
def get_last_seen_date(row: pandas.Series):
    """Find out when the user was last seen"""
    last_seen = pandas.to_datetime(row["password_last_used"])
    # Check each of the access keys
    for key_num in ["1", "2"]:
        key_date = pandas.to_datetime(
            row["access_key_{}_last_used_date".format(key_num)])
        # If password_last_used or an access key last used date is NaT, set
        # the current access key to last_seen
        if last_seen is pandas.NaT:
            last_seen = key_date
        # Compare if the key_date is more recent than last_seen or not
        elif last_seen < key_date:
            last_seen = key_date

    return last_seen

def check_unused_credential(row: pandas.Series, enabled: str,
                            last_used: str):
    """Check if the user has an active credential but it has never been used"""
    if row[enabled]:
        if row[last_used] is pandas.np.nan:
            return True
    return False

def needs_mfa(row: pandas.Series):
    """Check that if the user has a password, they also have mfa active"""
    if row["password_enabled"] and not row["mfa_active"]:
        return True
    else:
        return False

def needs_password_rotation(row: pandas.Series):
    """Check if their password has already expired (AWS will force them to
    change it on next login)
    """
    # Means they don't have console access and a password so don't need to
    # rotate a non-existent password
    if row["password_enabled"] is False:
        return False

    next_rotation_date = pandas.to_datetime(row["password_next_rotation"])
    if next_rotation_date <= pandas.datetime.today():
        return True
    else:
        return False

def needs_access_key_rotation(row: pandas.Series):
    """Check if an access key needs rotation"""
    def check_access_key_expiration(row: pandas.Series, key_num: str):
        """Check if access key age is past ACCESS_KEY_EXPIRATION_DAYS"""
        last_rotated = pandas.to_datetime(
            row["access_key_{}_last_rotated".format(key_num)])
        expiration_date = last_rotated + pandas.Timedelta(
            days=ACCESS_KEY_EXPIRATION_DAYS)

        if expiration_date < pandas.datetime.today():
            return True
        else:
            return False

    # If the key isn't active, it doesn't matter how old it is
    if row["access_key_1_active"]:
        result1 = check_access_key_expiration(row, "1")
    else:
        result1 = False
    if row["access_key_2_active"]:
        result2 = check_access_key_expiration(row, "2")
    else:
        result2 = False

    return (result1 or result2)

def multiple_access_keys_active(row: pandas.Series):
    """Check if multiple access keys are active"""
    if row["access_key_1_active"] and row["access_key_2_active"]:
        return True
    else:
        return False

def process_users():
    """Takes ALL_USERS_CSV, filters it down to active users and adds columns
    that indicate if attention is needed or not
    """
    users = pandas.read_csv(ALL_USERS_CSV, index_col="user")

    # Drop the root account since we can't control it and it prevents the
    # password_enabled column from being read as bools since it has
    # 'not_supported' as the value
    users = users.drop("<root_account>", axis=0)

    # Fix password_enabled to be read as bools
    users["password_enabled"] = users.password_enabled.replace(
        {"true": True, "false": False})

    # Filter down to just active users
    active_users_filter = users[(users["password_enabled"]==True) |
                                (users["access_key_1_active"]==True) |
                                (users["access_key_2_active"]==True)]

    # Get rid of inactive users since they don't matter and pandas doesn't like
    # applying a function to a filtered dataframe
    active_users = active_users_filter.copy()

    # Add column of the timestamp the user was last seen
    active_users["last_seen"] = active_users.apply(
        get_last_seen_date, axis=1)

    # Add columns noting if a user has a credential but never used it
    for check in CREDENTIAL_CHECKS:
        active_users[check["column_name"]] = active_users.apply(
            check_unused_credential,
            args=(check["enabled"], check["last_used"]),
            axis=1)

    # Add column noting if the user needs to enable mfa or not
    active_users["needs_mfa"] = active_users.apply(needs_mfa, axis=1)

    # Add column noting if the user's password has expired or not
    active_users["needs_password_rotation"] = active_users.apply(
        needs_password_rotation, axis=1)

    # Add column noting if the user's access key is out of date or not
    active_users["needs_access_key_rotation"] = active_users.apply(
        needs_access_key_rotation, axis=1)

    # Add column noting if the user has multiple access keys active
    active_users["multiple_access_keys_active"] = active_users.apply(
        multiple_access_keys_active, axis=1)

    # Write dataframe with all columns to csv
    active_users.to_csv(ACTIVE_USERS_ALL_COLUMNS_CSV)
    print(f"{ACTIVE_USERS_ALL_COLUMNS_CSV} created")

    # Remove columns we no longer need so that the csv is more managable
    active_users.drop(COLUMNS_TO_REMOVE, axis=1, inplace=True)

    # Write slimmed down dataframe to csv
    active_users.to_csv(ACTIVE_USERS_CSV)
    print(f"{ACTIVE_USERS_CSV} created")

def main():
    get_all_users()
    process_users()

if __name__ == '__main__':
    main()

import functions
class Replace:
    def anonymize_usernames_in_raw_log(raw_log):
        for original, anonymized in functions.Functions.username_dictionary.items():
            print(original +" "+anonymized)
            raw_log = raw_log.replace(original, anonymized)
        return raw_log
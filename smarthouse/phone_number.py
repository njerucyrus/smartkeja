class CleanPhoneNumber(object):
    def __init__(self, phone_number):
        self.phone_number = phone_number

    def validate_phone_number(self):
        phone_number = self.phone_number
        phone = list(phone_number)
        prefix = phone[0]
        length = len(phone_number)

        if prefix == '0' and length == 10:
            phone[0] = '+254'
            return "".join(phone)

        elif prefix == '+' and length == 13:
            return str(phone_number)

        elif length < 10:
            print 'invalid phone number length'

        else:
            print 'invalid phone number'


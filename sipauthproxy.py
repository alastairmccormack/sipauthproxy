from mitmproxy import udp, ctx
import hashlib
import re
import os

KNOWN_PASSWORD = os.environ['PASS']

class SIPDigestModifier:
    def udp_message(self, flow: udp.UDPFlow):

        raw_message = flow.messages[-1]

        message = raw_message.content.decode(errors="ignore")

        # ctx.log.info(f"Recieved {message}")

        if "Authorization: Digest" in message:
            ctx.log.info(f"Modifying auth from {flow.client_conn.peername}")

            method = re.search(r'^\w+', message).group(0)

            # Extract the Authorization header
            auth_match = re.search(r'Authorization: Digest (.*)', message)
            if not auth_match:
                return

            auth_fields = dict(re.findall(r'(\w+)=["]?([^",\r\n]+)["]?', auth_match.group(1)))
            try:
                username = auth_fields["username"]
                realm = auth_fields["realm"]
                nonce = auth_fields["nonce"]
                uri = auth_fields["uri"]

                qop = auth_fields.get("qop")
                nonce_count = auth_fields.get("nc")
                client_nonce = auth_fields.get("cnonce")

                ha1 = hashlib.md5(f"{username}:{realm}:{KNOWN_PASSWORD}".encode()).hexdigest()
                ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

                if qop == 'auth':
                    new_response = hashlib.md5(f"{ha1}:{nonce}:{nonce_count}:{client_nonce}:{qop}:{ha2}".encode()).hexdigest()
                else:
                    new_response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

                # Replace the response= value in the header
                original_auth = auth_match.group(0)
                modified_auth = re.sub(r'response="[^"]+"', f'response="{new_response}"', original_auth)

                ctx.log.info(f'{original_auth=}')
                ctx.log.info(f'{modified_auth=}')

                new_message = message.replace(original_auth, modified_auth)
                ctx.log.warn(f'{new_message=}')
                flow.messages[-1].content = new_message.encode()

            except KeyError as e:
                ctx.log.warn(f"Missing digest field: {e}")

        # ctx.log.info(f'{flow.messages=}')

addons = [SIPDigestModifier()]
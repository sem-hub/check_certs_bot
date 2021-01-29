import logging
import rpyc

def send_to_chat(chat_id:int, msg: str):
    logger = logging.getLogger(__name__)
    try:
        rcon = rpyc.connect('localhost', 18861)
        rcon.root.add_message(chat_id, msg)
    except ConnectionError as error:
        logger.error(f'Connection to chat server error: {str(error)}')
        logger.info(msg)

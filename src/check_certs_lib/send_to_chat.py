import logging
import rpyc

def send_to_chats(msg: str, chat_ids: list):
    logger = logging.getLogger(__name__)
    try:
        rcon = rpyc.connect('localhost', 18861)
        for chat_id in chat_ids:
            rcon.root.add_message(chat_id, msg)
    except ConnectionError as error:
        logger.error(f'Connection to chat server error: {str(error)}')
        logger.info(msg)

#!/usr/bin/env python3

import time
import argparse
import configparser

import socks

import vk
import telethon.sync as telethon
import telethon.tl.functions as tgapi
import telethon.tl.types as tgtype
import telethon.errors as tgerror
import telethon.events as tgevent
import telethon.sessions as tgauth
import telethon.network.connection as tgmode

APP_DESCRIPTION = "tg2vk, a gate from Telegram channel to VKontakte group.\n" \
    "written by Dmitry D. Chernov aka BlackDoomer (blackdoomer@yandex.ru)"

CONFIG_SECTION_TELEGRAM = "telegram"
CONFIG_SECTION_VKONTAKTE = "vkontakte"
CONFIG_SECTION_ACCESS = "access"

OPTION_TELEGRAM_SOURCE = (CONFIG_SECTION_TELEGRAM, "source_channel")
OPTION_VKONTAKTE_TARGET = (CONFIG_SECTION_VKONTAKTE, "target_group")

OPTION_ACCESS_VKTOKEN = (CONFIG_SECTION_ACCESS, "vk_token")
OPTION_ACCESS_TGSESSION = (CONFIG_SECTION_ACCESS, "tg_session")


def init_interactive(config_file, tg_client):
    if not config_file.has_section(CONFIG_SECTION_ACCESS):
        config_file.add_section(CONFIG_SECTION_ACCESS)

    # VKontakte authorization
    if not config_file.has_option(*OPTION_ACCESS_VKTOKEN):
        vk_session = vk.InteractiveAuthSession(
            app_id=config_file.get(CONFIG_SECTION_VKONTAKTE, "app_id"),
            scope='wall,groups,offline'
        )
        config_file.set(*OPTION_ACCESS_VKTOKEN, vk_session.access_token)

    # Telegram authorization
    if not config_file.has_option(*OPTION_ACCESS_TGSESSION):
        tg_client.start(
            phone=lambda: input("Telegram account phone number: "),
            first_name=None
        )
        config_file.set(*OPTION_ACCESS_TGSESSION, tg_client.session.save())

def setup_interactive(config_file, tg_client, vk_api):
    # Setting Telegram source channel
    # TODO: Handle ChatsSlice
    channels = [x for x in (
        x for x in tg_client(tgapi.messages.GetAllChatsRequest([])).chats
        if isinstance(x, tgtype.Channel)
    ) if x.broadcast]  # TODO: Is x.broadcast == not x.megagroup?

    for idx, item in enumerate(channels):
        print("{:>4}: {}".format(idx, item.title))

    index = input("\nNumber of a Telegram channel you want to use as source:\n")
    config_file.set(*OPTION_TELEGRAM_SOURCE, str(channels[int(index)].id))

    # Setting VKontakte target channel
    domain_name = input("\nDomain name of a VKontakte group you want to use "
        "as target:\n")
    group = vk_api.utils.resolveScreenName(screen_name=domain_name)
    if group.get('type') != 'group':
        raise RuntimeError("this domain name doesn't belong to a group")
    config_file.set(*OPTION_VKONTAKTE_TARGET, str(group.get('object_id')))

def get_proxy_args(proxy_type, proxy_host, proxy_auth):
    if not proxy_type:
        return {}
    proxy_type = proxy_type.upper()
    proxy_host, proxy_port = proxy_host.split(":")
    proxy_port = int(proxy_port)

    if proxy_type == "MTPROTO":
        proxy_auth = proxy_auth.lower()
        mode_class = tgmode.ConnectionTcpMTProxyRandomizedIntermediate \
                     if proxy_auth.startswith("dd") else \
                     tgmode.ConnectionTcpMTProxyIntermediate
        return {
            'connection': mode_class,
            'proxy': (proxy_host, proxy_port, proxy_auth)
        }

    proxy_username, proxy_password, *_ = (*proxy_auth.split(":"), None, None)
    return {'proxy': {
        'proxy_type': socks.PROXY_TYPES[proxy_type],
        'addr': proxy_host,
        'port': proxy_port,
        'username': proxy_username,
        'password': proxy_password
    }}

def main(cmd_args):
    app_config = configparser.ConfigParser()
    app_config.read(cmd_args.config_file)

    proxy_type = app_config.get(
        CONFIG_SECTION_TELEGRAM, "proxy_type", fallback=None)
    proxy_host = app_config.get(
        CONFIG_SECTION_TELEGRAM, "proxy_host", fallback=None)
    proxy_auth = app_config.get(
        CONFIG_SECTION_TELEGRAM, "proxy_auth", fallback="")
    tg_session = app_config.get(
        *OPTION_ACCESS_TGSESSION, fallback=None)

    try:
        tg_client = telethon.TelegramClient(
            tgauth.StringSession(tg_session),
            app_config.get(CONFIG_SECTION_TELEGRAM, "api_id"),
            app_config.get(CONFIG_SECTION_TELEGRAM, "api_hash"),
            sequential_updates=True,
            **get_proxy_args(proxy_type, proxy_host, proxy_auth)
        )

        if cmd_args.init:
            init_interactive(app_config, tg_client)

        vk_api = vk.API(
            vk.Session(app_config.get(*OPTION_ACCESS_VKTOKEN)),
            version='5.95'
        )

        if cmd_args.setup:
            if not tg_client.is_connected():
                tg_client.connect()
            setup_interactive(app_config, tg_client, vk_api)

    finally:
        with open(cmd_args.config_file, 'w') as output_file:
            app_config.write(output_file)

    source_channel_id = int(app_config.get(*OPTION_TELEGRAM_SOURCE))
    target_group_id = -int(app_config.get(*OPTION_VKONTAKTE_TARGET))

    async def CB_tg_update_handler(event):
        # TODO: Make this fault tolerant.
        if event.message.to_id.channel_id != source_channel_id:
            return

        #print(event.stringify())
        print('\nsource id: {}\n{}\n'.format(
            event.message.id, event.message.message))
        result = vk_api.wall.post(
            owner_id=target_group_id,
            from_group=True,
            message=event.message.message,
            guid=str(event.message.id)
        )
        print('target id: {}\n'.format(result.get('post_id')))

    tg_client.add_event_handler(CB_tg_update_handler, tgevent.NewMessage)

    while True:
        try:
            if not tg_client.is_connected():
                print('attempting to connect to Telegram...')
                tg_client.connect()
                print('successfully connected')

            # since this performs a "high level request", Telegram will
            # understand that we need updates, so it should send them to us
            if not tg_client.is_user_authorized():
                raise tgerror.UnauthorizedError()

            # TODO: Call getChannelDifference and queue its result for posting.

            print('\nnow monitoring (press Ctrl+C to exit)')
            tg_client.loop.run_until_complete(tg_client.disconnected)

        except (SystemExit, KeyboardInterrupt):
            break

        except (tgerror.UnauthorizedError):
            raise

        except Exception as e:
            # just in case
            if tg_client.is_connected():
                tg_client.disconnect()
                print('sleeping, wait a while...')
                time.sleep(10)


if __name__ == '__main__':
    cmd_parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="%(prog)s - " + APP_DESCRIPTION)

    cmd_parser.add_argument(
        'config_file',
        help="name of the INI file with gate configuration")

    cmd_parser.add_argument(
        '-i', '--init', action='store_true',
        help="perform interactive authorizations to obtain all necessary "
            "access data for the specified configuration")

    cmd_parser.add_argument(
        '-s', '--setup', action='store_true',
        help="specify a source Telegram channel and a target VKontakte group")

    main(cmd_parser.parse_args())

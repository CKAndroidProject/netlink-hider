#### 介绍
一些厂商通过 netlink 绕过 Android 的限制来获得 mac 地址以追踪用户, 这个片段通过 HOOK 来伪造 netlink 返回的网络地址.


#### 示例

```C++
HOOK_DEF(ssize_t, recvmsg, int fd, msghdr *msg, int flags) {
    INIT_ORIG(recvmsg);
    auto rr = orig_recvmsg(fd, msg, flags);

    int type;
    int length = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &type, &length);
    if (type != AF_NETLINK) {
        return rr;
    }

    char *b = static_cast<char *>(msg->msg_iov->iov_base);
    auto *pstruNL = (struct nlmsghdr *) b;
    size_t r = msg->msg_iov->iov_len;

    ALOGW("recvmsg %d %d", r, pstruNL->nlmsg_len);
    while (NLMSG_OK(pstruNL, r)) {
        if (pstruNL->nlmsg_type == NLMSG_DONE) {
            ALOGW("recvmsg done");
            break;
        }

        if (pstruNL->nlmsg_type == NLMSG_ERROR) {
            ALOGW("recvmsg err");
            break;
        }

        auto *pstruIF = (ifinfomsg *) NLMSG_DATA(pstruNL);
        ALOGW("xx index %d ---", pstruIF->ifi_index);
        ALOGW("xx type %d", pstruIF->ifi_type);
        ALOGW("xx status %d", pstruIF->ifi_flags);

        rtattr *nameTarget = nullptr;
        ether_addr *macTarget = nullptr;

        rtattr *pattr = IFLA_RTA(pstruIF);
        int attrlen = NLMSG_PAYLOAD(pstruNL, sizeof(ifinfomsg));
        while (RTA_OK(pattr, attrlen)) {
            switch (pattr->rta_type) {
                case IFLA_IFNAME: {

                    if (strcmp((char *) RTA_DATA(pattr), "wlan0") == 0) {
                        nameTarget = pattr;
                    }

                    ALOGW("xx name %s", RTA_DATA(pattr));
                    break;
                }
                case IFLA_ADDRESS: {
                    if (pstruIF->ifi_type == ARPHRD_ETHER) {
                        macTarget = (ether_addr *) RTA_DATA(pattr);
                        ALOGW("xx addr %s", ether_ntoa(macTarget));
                    }
                    break;
                }
                default:
                    break;
            }

            pattr = RTA_NEXT(pattr, attrlen);
        }

        if (nameTarget != nullptr) {
            ALOGW("xx finded wlan0 mac, fake");

            auto fakemac = "00:00:00:00:00:00";

            std::vector<std::string> li;
            split(fakemac, li, ':');

            if (li.size() != 6) {
                ALOGE("mac size error");
                abort();
            }

            for (size_t i = 0; i < li.size(); i++) {
                char x = static_cast<char>(std::stoi(li[i], nullptr, 16));
                macTarget->ether_addr_octet[i] = x;
                ALOGW("fake mac in recvmsg to %02x %d", x, li.size());
            }
        }

        ALOGW("-------");
        pstruNL = NLMSG_NEXT(pstruNL, r);
    }
    return rr;
}
```

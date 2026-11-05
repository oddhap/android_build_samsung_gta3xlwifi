static unsigned long avc_decisions,packet_decisions,compound_packets,malformed_packets,null_security_packets,reload_probes,allow_count,deny_count;
static void check_capabilities(void) {
    unsigned supported=0x122f,accepted=0,rejected=0;
    for(unsigned bits=0;bits<(1U<<14);bits++){
        struct policydb p={0};for(unsigned bit=0;bit<14;bit++)if(bits&(1U<<bit))assert(!ebitmap_set_bit(&p.policycaps,bit,1));
        int rc=policydb_check_legacy_caps(&p);assert(rc==((bits&~supported)?-EOPNOTSUPP:0));
        if(rc)rejected++;else accepted++;ebitmap_destroy(&p.policycaps);
    }
    const unsigned unknown[]={63,64,255,4096};
    for(unsigned i=0;i<ARRAY_SIZE(unknown);i++){struct policydb p={0};assert(!ebitmap_set_bit(&p.policycaps,unknown[i],1));assert(policydb_check_legacy_caps(&p)==-EOPNOTSUPP);ebitmap_destroy(&p.policycaps);}
    fprintf(stderr,"CAPABILITIES: accepted=%u rejected=%u sparse_rejected=4\n",accepted,rejected);
    assert(accepted==128 && rejected==16256);
}
static u32 lookup_sym(unsigned index, const char *name) {
    void *datum = hashtab_search(policydb.symtab[index].table, name);
    assert(datum);
    return *(u32 *)datum;
}
static u32 make_sid(const char *type, unsigned cat) {
    struct context c;
    context_init(&c);
    c.user=lookup_sym(SYM_USERS,"u");c.role=lookup_sym(SYM_ROLES,"r");
    c.type=lookup_sym(SYM_TYPES,type);
    c.range.level[0].sens=c.range.level[1].sens=1;
    if(cat)for(unsigned l=0;l<2;l++)assert(!ebitmap_set_bit(&c.range.level[l].cat,cat-1,1));
    assert(policydb_context_isvalid(&policydb,&c));
    u32 sid;assert(!sidtab_context_to_sid(&sidtab,&c,&sid));context_destroy(&c);return sid;
}
int main(int argc,char **argv) {
    assert(argc==3);
    FILE *f=fopen(argv[1],"rb");assert(f && !fseek(f,0,SEEK_END));long length=ftell(f);assert(length>0);rewind(f);
    char *data=malloc(length);assert(data && fread(data,1,length,f)==(size_t)length);fclose(f);
    avtab_cache_init();check_capabilities();struct policy_file pf={data,(size_t)length};assert(!policydb_read(&policydb,&pf) && !pf.len);
    assert(!policydb_load_isids(&policydb,&sidtab));
    assert(!selinux_set_mapping(&policydb,secclass_map,&current_mapping,&current_mapping_size));
    /* Real loader capability decoding of the unmodified diagnostic input. */
    security_load_policycaps();assert(selinux_policycap_netlink_xperm==1);
    ss_initialized=1;latest_granting=19;
    f=fopen(argv[2],"r");assert(f);
    unsigned id,scat,tcat,base,driver;char sn[256],tn[256],cl[256];
    while(fscanf(f,"%u %255s %255s %255s %u %u %u %u",&id,sn,tn,cl,&scat,&tcat,&base,&driver)==8) {
        u32 s=make_sid(sn,scat),t=make_sid(tn,tcat);u16 pc=string_to_security_class(&policydb,cl),kc=map_class(pc);assert(pc && kc);
        struct av_decision raw={0},mapped={0};struct extended_perms xp={0};
        context_struct_compute_av(sidtab_search(&sidtab,s),sidtab_search(&sidtab,t),pc,&raw,&xp);
        security_compute_av(s,t,kc,&mapped,&xp);assert(mapped.seqno==19 && !lock_depth);
        struct extended_perms_data allow={0},audit={0},dont={0};struct extended_perms_decision xd={.allowed=&allow,.auditallow=&audit,.dontaudit=&dont};u32 seq=0;
        security_compute_xperms_decision(s,t,kc,driver,base,&xd,&seq);assert(seq==19 && !lock_depth);
        printf("%u %u %u %u %u %u %u %u %u",id,raw.allowed,raw.auditallow,raw.auditdeny,mapped.allowed,mapped.auditallow,mapped.auditdeny,xd.used,xp.base_perms);
        for(unsigned k=0;k<8;k++)printf(" %u",allow.p[k]);
        for(unsigned k=0;k<8;k++)printf(" %u",audit.p[k]);
        for(unsigned k=0;k<8;k++)printf(" %u",dont.p[k]);
        /* Compare actual AVC answers for every low-byte command with real policy decisions. */
        u32 request=0;const char *permission=base==AVC_EXT_IOCTL?"ioctl":"nlmsg";
        for(unsigned pi=0;secclass_map[kc-1].perms[pi];pi++)if(!strcmp(secclass_map[kc-1].perms[pi],permission))request=1U<<pi;
        assert(request);assert(!policydb.permissive_map.highbit);
        for(unsigned mode=0;mode<3;mode++) {
            reset_cache(mode);u32 granted[8]={0};
            if(mode==2){struct av_decision seed;struct avc_xperms_node xpseed;security_compute_av(s,t,kc,&seed,&xpseed.xp);rcu_read_lock();avc_insert(s,t,kc,&seed,&xpseed);rcu_read_unlock();
                struct extended_perms_data oa={0},ob={0},oc={0};struct extended_perms_decision other={.allowed=&oa,.auditallow=&ob,.dontaudit=&oc};u32 seq;
                security_compute_xperms_decision(s,t,kc,driver,base==AVC_EXT_IOCTL?AVC_EXT_NLMSG:AVC_EXT_IOCTL,&other,&seq);add_xpd(&other);
            }
            for(unsigned command=0;command<256;command++) {
                int rc=avc_has_extended_perms_seqno(s,t,kc,request,driver,base,command,NULL,latest_granting);
                assert(rc==0||rc==-EACCES);assert(!rcu_depth&&!lock_depth);avc_decisions++;if(rc)deny_count++;else allow_count++;
                if(!rc)security_xperm_set(granted,command);
            }
            for(unsigned k=0;k<8;k++)printf(" %u",granted[k]);
        }
        if(base==AVC_EXT_NLMSG)for(unsigned mode=0;mode<3;mode++) {
            reset_cache(mode);u32 granted[8]={0};actor_sid=s;
            struct sk_security_struct sksec={.sid=t,.sclass=kc};struct sock sk={.sk_security=&sksec};
            for(unsigned command=0;command<256;command++) {
                struct nlmsghdr header={.nlmsg_len=NLMSG_HDRLEN,.nlmsg_type=(driver<<8)|command};
                struct sk_buff skb={.len=sizeof(header),.data=(unsigned char *)&header};
                int rc=selinux_netlink_send(&sk,&skb);assert(rc==0||rc==-EACCES);assert(!lock_depth&&!rcu_depth);packet_decisions++;
                if(!rc)security_xperm_set(granted,command);
            }
            for(unsigned k=0;k<8;k++)printf(" %u",granted[k]);
            /* Compound skb outcomes must be the conjunction of independently checked single messages. */
            const unsigned pairs[][2]={{0,1},{16,18},{18,20},{31,32},{127,128},{254,255}};
            for(unsigned i=0;i<ARRAY_SIZE(pairs);i++) {
                struct nlmsghdr headers[2]={{.nlmsg_len=NLMSG_HDRLEN,.nlmsg_type=(driver<<8)|pairs[i][0]},
                    {.nlmsg_len=NLMSG_HDRLEN,.nlmsg_type=(driver<<8)|pairs[i][1]}};
                struct sk_buff skb={.len=sizeof(headers),.data=(unsigned char *)headers};
                int expected=security_xperm_test(granted,pairs[i][0])&&security_xperm_test(granted,pairs[i][1])?0:-EACCES;
                assert(selinux_netlink_send(&sk,&skb)==expected);compound_packets++;
            }
            /* Historical ignored malformed/short packets must never read past data or leak locks. */
            for(unsigned layout=0;layout<5;layout++) {
                struct nlmsghdr header={.nlmsg_len=layout==3?4:layout==4?100:16,.nlmsg_type=driver<<8};
                struct sk_buff skb={.len=layout<3?layout*7:16,.data=(unsigned char *)&header};
                assert(selinux_netlink_send(&sk,&skb)==0 && !rcu_depth&&!lock_depth);malformed_packets++;
            }
            struct nlmsghdr valid={.nlmsg_len=16,.nlmsg_type=driver<<8};struct sk_buff packet={.len=16,.data=(unsigned char *)&valid};
            sk.sk_security=NULL;assert(selinux_netlink_send(&sk,&packet)==-EFAULT);sk.sk_security=&sksec;null_security_packets++;
            if(mode==0 && (xp.base_perms&AVC_EXT_NLMSG)) {
                unsigned allowed=0;while(allowed<256&&!security_xperm_test(granted,allowed))allowed++;
                if(allowed<256)for(unsigned point=1;point<=3;point++) {
                    reset_cache(0);latest_granting=19;reload_after_unlocked=point;valid.nlmsg_type=(driver<<8)|allowed;
                    assert(selinux_netlink_send(&sk,&packet)==-EAGAIN && !rcu_depth&&!lock_depth && latest_granting==20);
                    reload_after_unlocked=0;latest_granting=19;reload_probes++;
                }
            }
        }
        printf("\n");
    }
    assert(feof(f));fclose(f);assert(allow_count && deny_count && reload_probes);
    fprintf(stderr,"COUNTS: avc=%lu packet=%lu compound=%lu malformed=%lu null_security=%lu reload=%lu allow=%lu deny=%lu\n",avc_decisions,packet_decisions,compound_packets,malformed_packets,null_security_packets,reload_probes,allow_count,deny_count);
    sidtab_destroy(&sidtab);policydb_destroy(&policydb);kfree(current_mapping);free(data);avtab_cache_destroy();return 0;
}

#if !(defined(GO) && defined(GOM) && defined(GO2) && defined(DATA))
#error meh!
#endif

GO(ov_bitrate,iFpi)
GO(ov_bitrate_instant,iFp)
GO(ov_clear,iFp)
GO(ov_comment,pFpi)
GO(ov_crosslap,iFpp)
GO(ov_fopen,iFpp)
GO(ov_halfrate,iFpi)
GO(ov_halfrate_p,iFp)
GO(ov_info,pFpi)
GO(ov_open,iFpppi)
GOM(ov_open_callbacks,iFEpppipppp)  // ov_callbaks are not "by ref", so all 4 values are just on the stack
GO(ov_pcm_seek,iFpI)
GO(ov_pcm_seek_lap,iFpi)
GO(ov_pcm_seek_page,iFpI)
GO(ov_pcm_seek_page_lap,iFpI)
GO(ov_pcm_tell,IFp)
GO(ov_pcm_total,IFpi)
GO(ov_raw_seek,iFpi)
GO(ov_raw_seek_lap,iFpi)
GO(ov_raw_tell,IFp)
GO(ov_raw_total,IFpi)
GO(ov_read,iFppiiiip)
//GO(ov_read_filter,iFppiiiipBp)
GO(ov_read_float,iFppip)
GO(ov_seekable,iFp)
GO(ov_serialnumber,iFpi)
GO(ov_streams,iFp)
GO(ov_test,iFpppi)
//GO(ov_test_callbacks,iFpppiS)
GO(ov_test_open,iFp)
GO(ov_time_seek,iFpd)
GO(ov_time_seek_lap,iFpd)
GO(ov_time_seek_page,iFpd)
GO(ov_time_seek_page_lap,iFpd)
GO(ov_time_tell,dFp)
GO(ov_time_total,dFpi)

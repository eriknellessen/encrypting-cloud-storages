/*
 * card-openpgp.c: Support for OpenPGP card
 *
 * Copyright (C) 2003  Olaf Kirch <okir@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * Specifications:
 * http://www.g10code.de/docs/openpgp-card-1.0.pdf (obsolete)
 * http://www.g10code.de/docs/openpgp-card-1.1.pdf
 * http://www.g10code.de/docs/openpgp-card-2.0.pdf
 * http://www.g10code.de/docs/openpgp-card-2.1.pdf (minor changes to v2.0)
 * http://www.g10code.de/docs/openpgp-card-3.0.pdf (not yet supported)
 */

#include <libopensc/opensc.h>
#include <libopensc/cards.h>
#include <libopensc/log.h>

static struct sc_card_operations *iso_ops;

//The following is just taken from openpgp-card.c. Update this, if openpgp-card.c is changed.
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libopensc/internal.h>
#include <libopensc/pkcs15.h>

static struct sc_card_operations *iso_ops;

/*
 * The OpenPGP card doesn't have a file system, instead everything
 * is stored in data objects that are accessed through GET/PUT.
 *
 * However, much inside OpenSC's pkcs15 implementation is based on
 * the assumption that we have a file system. So we fake one here.
 *
 * Selecting the MF causes us to select the OpenPGP AID.
 *
 * Everything else is mapped to "file" IDs.
 */

enum _type {		/* DO type */
	SIMPLE      = SC_FILE_TYPE_WORKING_EF,
	CONSTRUCTED = SC_FILE_TYPE_DF
};

enum _version {		/* 2-byte BCD-alike encoded version number */
	OPENPGP_CARD_1_0 = 0x0100,
	OPENPGP_CARD_1_1 = 0x0101,
	OPENPGP_CARD_2_0 = 0x0200,
	OPENPGP_CARD_2_1 = 0x0201,
	OPENPGP_CARD_3_0 = 0x0300
};

enum _access {		/* access flags for the respective DO/file */
	READ_NEVER   = 0x0010,
	READ_PIN1    = 0x0011,
	READ_PIN2    = 0x0012,
	READ_PIN3    = 0x0014,
	READ_ALWAYS  = 0x0018,
	READ_MASK    = 0x00FF,
	WRITE_NEVER  = 0x1000,
	WRITE_PIN1   = 0x1100,
	WRITE_PIN2   = 0x1200,
	WRITE_PIN3   = 0x1400,
	WRITE_ALWAYS = 0x1800,
	WRITE_MASK   = 0x1F00
};

enum _ext_caps {	/* extended capabilities/features */
	EXT_CAP_ALG_ATTR_CHANGEABLE = 0x0004,
	EXT_CAP_PRIVATE_DO          = 0x0008,
	EXT_CAP_C4_CHANGEABLE       = 0x0010,
	EXT_CAP_KEY_IMPORT          = 0x0020,
	EXT_CAP_GET_CHALLENGE       = 0x0040,
	EXT_CAP_SM                  = 0x0080,
	EXT_CAP_CHAINING            = 0x1000,
	EXT_CAP_APDU_EXT            = 0x2000
};

enum _card_state {
	CARD_STATE_UNKNOWN        = 0x00,
	CARD_STATE_INITIALIZATION = 0x03,
	CARD_STATE_ACTIVATED      = 0x05
};

typedef struct pgp_blob {
	struct pgp_blob *	next;	/* pointer to next sibling */
	struct pgp_blob *	parent;	/* pointer to parent */
	struct do_info *info;

	sc_file_t *	file;
	unsigned int	id;
	int		status;

	unsigned char *	data;
	unsigned int	len;
	struct pgp_blob *	files;	/* pointer to 1st child */
} pgp_blob_t;

struct do_info {
	unsigned int	id;		/* ID of the DO in question */

	enum _type	type;		/* constructed DO or not */
	enum _access	access;		/* R/W access levels for the DO */

	/* function to get the DO from the card:
	 * only != NULL is DO if readable and not only a part of a constructed DO */
	int		(*get_fn)(sc_card_t *, unsigned int, u8 *, size_t);
	/* function to write the DO to the card:
	 * only != NULL if DO is writeable under some conditions */
	int		(*put_fn)(sc_card_t *, unsigned int, const u8 *, size_t);
};

static int		pgp_get_card_features(sc_card_t *card);
static int		pgp_finish(sc_card_t *card);
static void		pgp_iterate_blobs(pgp_blob_t *, int, void (*func)());

static int		pgp_get_blob(sc_card_t *card, pgp_blob_t *blob,
				 unsigned int id, pgp_blob_t **ret);
static pgp_blob_t *	pgp_new_blob(sc_card_t *, pgp_blob_t *, unsigned int, sc_file_t *);
static void		pgp_free_blob(pgp_blob_t *);
static int		pgp_get_pubkey(sc_card_t *, unsigned int,
				u8 *, size_t);
static int		pgp_get_pubkey_pem(sc_card_t *, unsigned int,
				u8 *, size_t);

/* The DO holding X.509 certificate is constructed but does not contain a child DO.
 * We should notice this when building fake file system later. */
#define DO_CERT                  0x7f21
/* Control Reference Template of private keys. Ref: Section 4.3.3.7 of OpenPGP card v2 spec.
 * Here we treat them as DOs just for convenience */
#define DO_SIGN                  0xb600
#define DO_ENCR                  0xb800
#define DO_AUTH                  0xa400
/* These DOs do not exist. They are defined and used just for ease of implementation */
#define DO_SIGN_SYM              0xb601
#define DO_ENCR_SYM              0xb801
#define DO_AUTH_SYM              0xa401
/* Private DOs */
#define DO_PRIV1                 0x0101
#define DO_PRIV2                 0x0102
#define DO_PRIV3                 0x0103
#define DO_PRIV4                 0x0104
/* Cardholder information DOs */
#define DO_CARDHOLDER            0x65
#define DO_NAME                  0x5b
#define DO_LANG_PREF             0x5f2d
#define DO_SEX                   0x5f35


/* Maximum length for response buffer when reading pubkey.
 * This value is calculated with 4096-bit key length */
#define MAXLEN_RESP_PUBKEY       527
/* Gnuk only supports 1 key length (2048 bit) */
#define MAXLEN_RESP_PUBKEY_GNUK  271

static struct do_info		pgp1_objects[] = {	/* OpenPGP card spec 1.1 */
	{ 0x004f, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x005b, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x005e, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0065, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x006e, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x0073, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x007a, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x0081, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x0082, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x0093, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c0, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c1, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c2, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c3, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c4, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c5, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c6, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c7, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c8, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c9, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00ca, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cb, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cc, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cd, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00ce, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cf, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d0, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00e0, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00e1, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00e2, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x0101, SIMPLE,      READ_ALWAYS | WRITE_PIN2,  sc_get_data,        sc_put_data },
	{ 0x0102, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0103, SIMPLE,      READ_PIN2   | WRITE_PIN2,  sc_get_data,        sc_put_data },
	{ 0x0104, SIMPLE,      READ_PIN3   | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x3f00, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x5f2d, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f35, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f50, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x7f49, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ DO_AUTH,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_AUTH_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ DO_SIGN,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_SIGN_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ DO_ENCR,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_ENCR_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ 0, 0, 0, NULL, NULL },
};

static struct do_info		pgp2_objects[] = {	/* OpenPGP card spec 2.0 */
	{ 0x004d, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x004f, SIMPLE,      READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x005b, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x005e, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0065, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x006e, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x0073, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x007a, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x0081, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x0082, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x0093, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c0, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c1, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c2, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c3, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c4, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x00c5, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c6, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c7, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c8, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c9, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00ca, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cb, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cc, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cd, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00ce, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cf, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d0, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d1, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d2, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d3, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00f4, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x0101, SIMPLE,      READ_ALWAYS | WRITE_PIN2,  sc_get_data,        sc_put_data },
	{ 0x0102, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0103, SIMPLE,      READ_PIN2   | WRITE_PIN2,  sc_get_data,        sc_put_data },
	{ 0x0104, SIMPLE,      READ_PIN3   | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x3f00, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x5f2d, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f35, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f48, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f50, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x5f52, SIMPLE,      READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	/* The 7F21 is constructed DO in spec, but in practice, its content can be retrieved
	 * as simple DO (no need to parse TLV). */
	{ DO_CERT, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x7f48, CONSTRUCTED, READ_NEVER  | WRITE_NEVER, NULL,               NULL        },
	{ 0x7f49, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ DO_AUTH,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	/* The 0xA401, 0xB601, 0xB801 are just symbolic, it does not represent any real DO.
	 * However, their R/W access condition may block the process of importing key in pkcs15init.
	 * So we set their accesses condition as WRITE_PIN3 (writable). */
	{ DO_AUTH_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ DO_SIGN,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_SIGN_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ DO_ENCR,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_ENCR_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ 0, 0, 0, NULL, NULL },
};

#define DRVDATA(card)        ((struct pgp_priv_data *) ((card)->drv_data))
struct pgp_priv_data {
	pgp_blob_t *		mf;
	pgp_blob_t *		current;	/* currently selected file */

	enum _version		bcd_version;
	struct do_info		*pgp_objects;

	enum _card_state	state;		/* card state */
	enum _ext_caps		ext_caps;	/* extended capabilities */

	size_t			max_challenge_size;
	size_t			max_cert_size;

	sc_security_env_t	sec_env;
};

/**
 * Internal: get features of the card: capabilities, ...
 */
static int
pgp_get_card_features(sc_card_t *card)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	unsigned char *hist_bytes = card->atr.value;
	size_t atr_len = card->atr.len;
	size_t i;
	pgp_blob_t *blob, *blob6e, *blob73;

	/* parse card capabilities from historical bytes */
	for (i = 0; (i < atr_len) && (hist_bytes[i] != 0x73); i++)
		;
	/* IS07816-4 hist bytes 3rd function table */
	if ((hist_bytes[i] == 0x73) && (atr_len > i+3)) {
		/* bit 0x40 in byte 3 of TL 0x73 means "extended Le/Lc" */
		if (hist_bytes[i+3] & 0x40) {
			card->caps |= SC_CARD_CAP_APDU_EXT;
			priv->ext_caps |= EXT_CAP_APDU_EXT;
		}
		/* bit 0x80 in byte 3 of TL 0x73 means "Command chaining" */
		if (hist_bytes[i+3] & 0x80)
			priv->ext_caps |= EXT_CAP_CHAINING;
	}

	if (priv->bcd_version >= OPENPGP_CARD_2_0) {
		/* get card capabilities from "historical bytes" DO */
		if ((pgp_get_blob(card, priv->mf, 0x5f52, &blob) >= 0) &&
		    (blob->data != NULL) && (blob->data[0] == 0x00)) {

			/* find beginning of "interesting" bytes */
			for (i = 0; (i < blob->len) && (blob->data[i] != 0x73); i++)
				;
			/* IS07816-4 hist bytes 3rd function table */
			if ((blob->data[i] == 0x73) && (blob->len > i+3)) {
				/* bit 0x40 in byte 3 of TL 0x73 means "extended Le/Lc" */
				if (blob->data[i+3] & 0x40) {
					card->caps |= SC_CARD_CAP_APDU_EXT;
					priv->ext_caps |= EXT_CAP_APDU_EXT;
				}
				/* bit 0x80 in byte 3 of TL 0x73 means "Command chaining" */
				if (blob->data[i+3] & 0x80)
					priv->ext_caps |= EXT_CAP_CHAINING;
			}

			/* get card status from historical bytes status indicator */
			if ((blob->data[0] == 0x00) && (blob->len >= 4))
				priv->state = blob->data[blob->len-3];
		}
	}

	if ((pgp_get_blob(card, priv->mf, 0x006e, &blob6e) >= 0) &&
	    (pgp_get_blob(card, blob6e, 0x0073, &blob73) >= 0)) {

		/* get "extended capabilities" DO */
		if ((pgp_get_blob(card, blob73, 0x00c0, &blob) >= 0) &&
		    (blob->data != NULL) && (blob->len > 0)) {
			/* in v2.0 bit 0x04 in first byte means "algorithm attributes changeable */
			if ((blob->data[0] & 0x04) &&
				(card->type == SC_CARD_TYPE_OPENPGP_V2 || card->type == SC_CARD_TYPE_OPENPGP_GNUK))
				priv->ext_caps |= EXT_CAP_ALG_ATTR_CHANGEABLE;
			/* bit 0x08 in first byte means "support for private use DOs" */
			if (blob->data[0] & 0x08)
				priv->ext_caps |= EXT_CAP_PRIVATE_DO;
			/* bit 0x10 in first byte means "support for CHV status byte changeable" */
			if (blob->data[0] & 0x10)
				priv->ext_caps |= EXT_CAP_C4_CHANGEABLE;
			/* bit 0x20 in first byte means "support for Key Import" */
			if (blob->data[0] & 0x20)
				priv->ext_caps |= EXT_CAP_KEY_IMPORT;
			/* bit 0x40 in first byte means "support for Get Challenge" */
			if (blob->data[0] & 0x40) {
				card->caps |= SC_CARD_CAP_RNG;
				priv->ext_caps |= EXT_CAP_GET_CHALLENGE;
			}
			/* in v2.0 bit 0x80 in first byte means "support Secure Messaging" */
			if ((blob->data[0] & 0x80) &&
				(card->type == SC_CARD_TYPE_OPENPGP_V2 || card->type == SC_CARD_TYPE_OPENPGP_GNUK))
				priv->ext_caps |= EXT_CAP_SM;

			if ((priv->bcd_version >= OPENPGP_CARD_2_0) && (blob->len >= 10)) {
				/* max. challenge size is at bytes 3-4 */
				priv->max_challenge_size = bebytes2ushort(blob->data + 2);
				/* max. cert size it at bytes 5-6 */
				priv->max_cert_size = bebytes2ushort(blob->data + 4);
				/* max. send/receive sizes are at bytes 7-8 resp. 9-10 */
				card->max_send_size = bebytes2ushort(blob->data + 6);
				card->max_recv_size = bebytes2ushort(blob->data + 8);
			}
		}

		/* get max. PIN length from "CHV status bytes" DO */
		if ((pgp_get_blob(card, blob73, 0x00c4, &blob) >= 0) &&
			(blob->data != NULL) && (blob->len > 1)) {
			/* 2nd byte in "CHV status bytes" DO means "max. PIN length" */
			card->max_pin_len = blob->data[1];
		}

		/* get supported algorithms & key lengths from "algorithm attributes" DOs */
		for (i = 0x00c1; i <= 0x00c3; i++) {
			unsigned long flags;

			/* Is this correct? */
			/* OpenPGP card spec 1.1 & 2.0, section 2.1 */
			flags = SC_ALGORITHM_RSA_RAW;
			/* OpenPGP card spec 1.1 & 2.0, section 7.2.9 & 7.2.10 */
			flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
			flags |= SC_ALGORITHM_RSA_HASH_NONE;
			/* Can be generated in card */
			flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;

			if ((pgp_get_blob(card, blob73, i, &blob) >= 0) &&
				(blob->data != NULL) && (blob->len >= 4)) {
				if (blob->data[0] == 0x01) {	/* Algorithm ID [RFC4880]: RSA */
					unsigned int keylen = bebytes2ushort(blob->data + 1);  /* Measured in bit */

					_sc_card_add_rsa_alg(card, keylen, flags, 0);
				}
			}
		}
	}

	return SC_SUCCESS;
}


/**
 * ABI: terminate driver.
 */
static int
pgp_finish(sc_card_t *card)
{
	if (card != NULL) {
		struct pgp_priv_data *priv = DRVDATA(card);

		if (priv != NULL) {
			/* delete fake file hierarchy */
			pgp_iterate_blobs(priv->mf, 99, pgp_free_blob);

			/* delete private data */
			free(priv);
		}
		card->drv_data = NULL;
	}
	return SC_SUCCESS;
}


/**
 * Internal: fill a blob's data.
 */
static int
pgp_set_blob(pgp_blob_t *blob, const u8 *data, size_t len)
{
	if (blob->data)
		free(blob->data);
	blob->data = NULL;
	blob->len    = 0;
	blob->status = 0;

	if (len > 0) {
		void *tmp = calloc(len, 1);

		if (tmp == NULL)
			return SC_ERROR_OUT_OF_MEMORY;

		blob->data = tmp;
		blob->len  = (unsigned int)len;
		if (data != NULL)
			memcpy(blob->data, data, len);
	}

	if (blob->file)
		blob->file->size = len;

	return SC_SUCCESS;
}


/**
 * Internal: implement Access Control List for emulated file.
 * The Access Control is derived from the DO access permission.
 **/
static void
pgp_attach_acl(sc_card_t *card, sc_file_t *file, struct do_info *info)
{
	unsigned int method = SC_AC_NONE;
	unsigned long key_ref = SC_AC_KEY_REF_NONE;

	/* Write access */
	switch (info->access & WRITE_MASK) {
	case WRITE_NEVER:
		method = SC_AC_NEVER;
		break;
	case WRITE_PIN1:
		method = SC_AC_CHV;
		key_ref = 0x01;
		break;
	case WRITE_PIN2:
		method = SC_AC_CHV;
		key_ref = 0x02;
		break;
	case WRITE_PIN3:
		method = SC_AC_CHV;
		key_ref = 0x03;
		break;
	}

	if (method != SC_AC_NONE || key_ref != SC_AC_KEY_REF_NONE) {
		sc_file_add_acl_entry(file, SC_AC_OP_WRITE, method, key_ref);
		sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, method, key_ref);
		sc_file_add_acl_entry(file, SC_AC_OP_DELETE, method, key_ref);
		sc_file_add_acl_entry(file, SC_AC_OP_CREATE, method, key_ref);
	}
	else {
		/* When SC_AC_OP_DELETE is absent, we need to provide
		 * SC_AC_OP_DELETE_SELF for sc_pkcs15init_delete_by_path() */
		sc_file_add_acl_entry(file, SC_AC_OP_DELETE_SELF, method, key_ref);
	}

	method = SC_AC_NONE;
	key_ref = SC_AC_KEY_REF_NONE;
	/* Read access */
	switch (info->access & READ_MASK) {
	case READ_NEVER:
		method = SC_AC_NEVER;
		break;
	case READ_PIN1:
		method = SC_AC_CHV;
		key_ref = 0x01;
		break;
	case READ_PIN2:
		method = SC_AC_CHV;
		key_ref = 0x02;
		break;
	case READ_PIN3:
		method = SC_AC_CHV;
		key_ref = 0x03;
		break;
	}

	if (method != SC_AC_NONE || key_ref != SC_AC_KEY_REF_NONE) {
		sc_file_add_acl_entry(file, SC_AC_OP_READ, method, key_ref);
	}
}


/**
 * Internal: append a blob to the list of children of a given parent blob.
 */
static pgp_blob_t *
pgp_new_blob(sc_card_t *card, pgp_blob_t *parent, unsigned int file_id,
		sc_file_t *file)
{
	pgp_blob_t *blob = NULL;

	if (file == NULL)
		return NULL;

	if ((blob = calloc(1, sizeof(pgp_blob_t))) != NULL) {
		struct pgp_priv_data *priv = DRVDATA(card);
		struct do_info *info;

		blob->file = file;

		blob->file->type         = SC_FILE_TYPE_WORKING_EF; /* default */
		blob->file->ef_structure = SC_FILE_EF_TRANSPARENT;
		blob->file->id           = file_id;

		blob->id     = file_id;
		blob->parent = parent;

		if (parent != NULL) {
			pgp_blob_t **p;

			/* set file's path = parent's path + file's id */
			blob->file->path = parent->file->path;
			sc_append_file_id(&blob->file->path, file_id);

			/* append blob to list of parent's children */
			for (p = &parent->files; *p != NULL; p = &(*p)->next)
				;
			*p = blob;
		}
		else {
			u8 id_str[2];

			/* no parent: set file's path = file's id */
			/* FIXME sc_format_path expects an hex string of a file
			 * identifier. ushort2bebytes instead delivers a two bytes binary
			 * string */
			sc_format_path((char *) ushort2bebytes(id_str, file_id), &blob->file->path);
		}

		/* find matching DO info: set file type depending on it */
		for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++) {
			if (info->id == file_id) {
				blob->info = info;
				blob->file->type = blob->info->type;
				pgp_attach_acl(card, blob->file, info);
				break;
			}
		}
	}

	return blob;
}


/**
 * Internal: free a blob including its content.
 */
static void
pgp_free_blob(pgp_blob_t *blob)
{
	if (blob) {
		if (blob->parent) {
			pgp_blob_t **p;

			/* remove blob from list of parent's children */
			for (p = &blob->parent->files; *p != NULL && *p != blob; p = &(*p)->next)
				;
			if (*p == blob)
				*p = blob->next;
		}

		if (blob->file)
			sc_file_free(blob->file);
		if (blob->data)
			free(blob->data);
		free(blob);
	}
}


/**
 * Internal: iterate through the blob tree, calling a function for each blob.
 */
static void
pgp_iterate_blobs(pgp_blob_t *blob, int level, void (*func)())
{
	if (blob) {
		if (level > 0) {
			pgp_blob_t *child = blob->files;

			while (child != NULL) {
				pgp_blob_t *next = child->next;

				pgp_iterate_blobs(child, level-1, func);
				child = next;
			}
		}
		func(blob);
	}
}


/**
 * Internal: read a blob's contents from card.
 */
static int
pgp_read_blob(sc_card_t *card, pgp_blob_t *blob)
{
	struct pgp_priv_data *priv = DRVDATA(card);

	if (blob->data != NULL)
		return SC_SUCCESS;
	if (blob->info == NULL)
		return blob->status;

	if (blob->info->get_fn) {	/* readable, top-level DO */
		u8 	buffer[2048];
		size_t	buf_len = sizeof(buffer);
		int r = SC_SUCCESS;

		/* buffer length for certificate */
		if (blob->id == DO_CERT && priv->max_cert_size > 0) {
			buf_len = MIN(priv->max_cert_size, sizeof(buffer));
		}

		/* buffer length for Gnuk pubkey */
		if (card->type == SC_CARD_TYPE_OPENPGP_GNUK &&
		    (blob->id == DO_AUTH ||
		     blob->id == DO_SIGN ||
		     blob->id == DO_ENCR ||
		     blob->id == DO_AUTH_SYM ||
		     blob->id == DO_SIGN_SYM ||
		     blob->id == DO_ENCR_SYM)) {
			buf_len = MAXLEN_RESP_PUBKEY_GNUK;
		}

		r = blob->info->get_fn(card, blob->id, buffer, buf_len);

		if (r < 0) {	/* an error occurred */
			blob->status = r;
			return r;
		}

		return pgp_set_blob(blob, buffer, r);
	}
	else {		/* un-readable DO or part of a constructed DO */
		return SC_SUCCESS;
	}
}


/*
 * Internal: enumerate contents of a data blob.
 * The OpenPGP card has a TLV encoding according ASN.1 BER-encoding rules.
 */
static int
pgp_enumerate_blob(sc_card_t *card, pgp_blob_t *blob)
{
	const u8	*in;
	int		r;

	if (blob->files != NULL)
		return SC_SUCCESS;

	if ((r = pgp_read_blob(card, blob)) < 0)
		return r;

	in = blob->data;

	while ((int) blob->len > (in - blob->data)) {
		unsigned int	cla, tag, tmptag;
		size_t		len;
		const u8	*data = in;
		pgp_blob_t	*new;

		r = sc_asn1_read_tag(&data, blob->len - (in - blob->data),
					&cla, &tag, &len);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				 "Unexpected end of contents\n");
			return SC_ERROR_OBJECT_NOT_VALID;
		}

		/* undo ASN1's split of tag & class */
		for (tmptag = tag; tmptag > 0x0FF; tmptag >>= 8) {
			cla <<= 8;
		}
		tag |= cla;

		/* Awful hack for composite DOs that have
		 * a TLV with the DO's id encompassing the
		 * entire blob. Example: Yubikey Neo */
		if (tag == blob->id) {
			in = data;
			continue;
		}

		/* create fake file system hierarchy by
		 * using constructed DOs as DF */
		if ((new = pgp_new_blob(card, blob, tag, sc_file_new())) == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		pgp_set_blob(new, data, len);
		in = data + len;
	}

	return SC_SUCCESS;
}


/**
 * Internal: find a blob by ID below a given parent, filling its contents when necessary.
 */
static int
pgp_get_blob(sc_card_t *card, pgp_blob_t *blob, unsigned int id,
		pgp_blob_t **ret)
{
	pgp_blob_t		*child;
	int			r;

	if ((r = pgp_enumerate_blob(card, blob)) < 0)
		return r;

	for (child = blob->files; child; child = child->next) {
		if (child->id == id) {
			(void) pgp_read_blob(card, child);
			*ret = child;
			return SC_SUCCESS;
		}
	}

	/* This part is for "NOT FOUND" cases */

	/* Special case:
	 * Gnuk does not have default value for children of DO 65 (DOs 5B, 5F2D, 5F35)
	 * So, if these blob was not found, we create it. */
	if (blob->id == DO_CARDHOLDER && (id == DO_NAME || id == DO_LANG_PREF || id == DO_SEX)) {
		sc_log(card->ctx, "Create blob %X under %X", id, blob->id);
		child = pgp_new_blob(card, blob, id, sc_file_new());
		if (child) {
			pgp_set_blob(child, NULL, 0);
			*ret = child;
			return SC_SUCCESS;
		}
		else
			sc_log(card->ctx, "Not enough memory to create blob for DO %X");
	}

	return SC_ERROR_FILE_NOT_FOUND;
}


/**
 * Internal: search recursively for a blob by ID below a given root.
 */
static int
pgp_seek_blob(sc_card_t *card, pgp_blob_t *root, unsigned int id,
		pgp_blob_t **ret)
{
	pgp_blob_t	*child;
	int			r;

	if ((r = pgp_get_blob(card, root, id, ret)) == 0)
		/* the sought blob is right under root */
		return r;

	/* not found, seek deeper */
	for (child = root->files; child; child = child->next) {
		/* The DO of SIMPLE type or the DO holding certificate
		 * does not contain children */
		if (child->info->type == SIMPLE || child->id == DO_CERT)
			continue;
		r = pgp_seek_blob(card, child, id, ret);
		if (r == 0)
			return r;
	}

	return SC_ERROR_FILE_NOT_FOUND;
}


/**
 * Internal: find a blob by tag - pgp_seek_blob with optimizations.
 */
static pgp_blob_t *
pgp_find_blob(sc_card_t *card, unsigned int tag)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t *blob = NULL;
	int r;

	/* check if current selected blob is which we want to test */
	if (priv->current->id == tag) {
		return priv->current;
	}
	/* look for the blob representing the DO */
	r = pgp_seek_blob(card, priv->mf, tag, &blob);
	if (r < 0) {
		sc_log(card->ctx, "Failed to seek the blob representing the tag %04X. Error %d.", tag, r);
		return NULL;
	}
	return blob;
}

/**
 * Internal: get public key from card: as DF + sub-wEFs.
 */
static int
pgp_get_pubkey(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	sc_apdu_t	apdu;
	u8 apdu_case = (card->type == SC_CARD_TYPE_OPENPGP_GNUK)
			? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_4;
	u8		idbuf[2];
	int		r;

	sc_log(card->ctx, "called, tag=%04x\n", tag);

	sc_format_apdu(card, &apdu, apdu_case, 0x47, 0x81, 0);
	apdu.lc = 2;
	apdu.data = ushort2bebytes(idbuf, tag);
	apdu.datalen = 2;
	apdu.le = ((buf_len >= 256) && !(card->caps & SC_CARD_CAP_APDU_EXT)) ? 256 : buf_len;
	apdu.resp = buf;
	apdu.resplen = buf_len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}


/**
 * Internal: get public key from card: as one wEF.
 */
static int
pgp_get_pubkey_pem(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t	*blob, *mod_blob, *exp_blob;
	sc_pkcs15_pubkey_t pubkey;
	u8		*data;
	size_t		len;
	int		r;

	sc_log(card->ctx, "called, tag=%04x\n", tag);

	if ((r = pgp_get_blob(card, priv->mf, tag & 0xFFFE, &blob)) < 0
		|| (r = pgp_get_blob(card, blob, 0x7F49, &blob)) < 0
		|| (r = pgp_get_blob(card, blob, 0x0081, &mod_blob)) < 0
		|| (r = pgp_get_blob(card, blob, 0x0082, &exp_blob)) < 0
		|| (r = pgp_read_blob(card, mod_blob)) < 0
		|| (r = pgp_read_blob(card, exp_blob)) < 0)
		LOG_TEST_RET(card->ctx, r, "error getting elements");

	memset(&pubkey, 0, sizeof(pubkey));
	pubkey.algorithm = SC_ALGORITHM_RSA;
	pubkey.u.rsa.modulus.data  = mod_blob->data;
	pubkey.u.rsa.modulus.len   = mod_blob->len;
	pubkey.u.rsa.exponent.data = exp_blob->data;
	pubkey.u.rsa.exponent.len  = exp_blob->len;

	r = sc_pkcs15_encode_pubkey(card->ctx, &pubkey, &data, &len);
	LOG_TEST_RET(card->ctx, r, "public key encoding failed");

	if (len > buf_len)
		len = buf_len;
	memcpy(buf, data, len);
	free(data);

	LOG_FUNC_RETURN(card->ctx, (int)len);
}

//Here start our modifications
/**
 * ABI: initialize driver.
 */
#define BCD2CHAR(x) (((((x) & 0xF0) >> 4) * 10) + ((x) & 0x0F))

static u8 openpgpAppletId[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
static int
pgp_modified_init(sc_card_t *card)
{
	struct pgp_priv_data *priv;
	sc_path_t	aid;
	sc_file_t	*file = NULL;
	struct do_info	*info;
	int		r;
	pgp_blob_t 	*child = NULL;

	LOG_FUNC_CALLED(card->ctx);

	priv = calloc (1, sizeof *priv);
	if (!priv)
		return SC_ERROR_OUT_OF_MEMORY;
	card->drv_data = priv;

	card->cla = 0x00;

	/* set pointer to correct list of card objects */
	priv->pgp_objects = (card->type == SC_CARD_TYPE_OPENPGP_V2 || card->type == SC_CARD_TYPE_OPENPGP_GNUK)
				? pgp2_objects : pgp1_objects;

	/* set detailed card version */
	priv->bcd_version = (card->type == SC_CARD_TYPE_OPENPGP_V2 || card->type == SC_CARD_TYPE_OPENPGP_GNUK)
				? OPENPGP_CARD_2_0 : OPENPGP_CARD_1_1;

	/* select application "OpenPGP" */
	/* This is not correct behavior. The OpenPGP card standard (http://g10code.com/docs/openpgp-card-3.0.pdf)
	 * states on page 39, that no data may be given as a response to the select applet apdu. But then,
	 * iso_ops->select_file will fail. */
	/*
	sc_format_path("D276:0001:2401", &aid);
	aid.type = SC_PATH_TYPE_DF_NAME;
	if ((r = iso_ops->select_file(card, &aid, &file)) < 0) {
		pgp_finish(card);
		LOG_FUNC_RETURN(card->ctx, r);
	}
	*/
	sc_apdu_t apdu;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 4, 0);
	apdu.lc = sizeof openpgpAppletId;
	apdu.data = openpgpAppletId;
	apdu.datalen = sizeof openpgpAppletId;
	apdu.resplen = 0;
	apdu.le = 0;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(sc_check_sw(card, apdu.sw1, apdu.sw2) != SC_SUCCESS)
		return 1;

	/* defensive programming check */
	/* file will not be != NULL, because we skipped the last step. */
	/*
	if (!file)   {
		pgp_finish(card);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_FOUND);
	}
	*/

	/* Always do this, because we skipped one step. */
	file = sc_file_new();
	//if (file->namelen != 16) {
		/* explicitly get the full aid */
		r = sc_get_data(card, 0x004F, file->name, sizeof file->name);
		if (r < 0) {
			pgp_finish(card);
			return r;
		}
		file->namelen = r;
	//}

	/* read information from AID */
	if (file->namelen == 16) {
		/* OpenPGP card spec 1.1 & 2.0, section 4.2.1 & 4.1.2.1 */
		priv->bcd_version = bebytes2ushort(file->name + 6);
		card->version.fw_major = card->version.hw_major = BCD2CHAR(file->name[6]);
		card->version.fw_minor = card->version.hw_minor = BCD2CHAR(file->name[7]);

		/* kludge: get card's serial number from manufacturer ID + serial number */
		memcpy(card->serialnr.value, file->name + 8, 6);
		card->serialnr.len = 6;
	}

	/* change file path to MF for re-use in MF */
	sc_format_path("3f00", &file->path);

	/* set up the root of our fake file tree */
	priv->mf = pgp_new_blob(card, NULL, 0x3f00, file);
	if (!priv->mf) {
		pgp_finish(card);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	/* select MF */
	priv->current = priv->mf;

	/* populate MF - add matching blobs listed in the pgp_objects table */
	for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++) {
		if (((info->access & READ_MASK) != READ_NEVER) &&
			(info->get_fn != NULL)) {
			child = pgp_new_blob(card, priv->mf, info->id, sc_file_new());

			/* catch out of memory condition */
			if (child == NULL) {
				pgp_finish(card);
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
			}
		}
	}

	/* get card_features from ATR & DOs */
	pgp_get_card_features(card);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	return 0;
}


/**
 * ABI: driver binding stuff.
 */
struct sc_card_driver *
sc_get_modified_openpgp_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	iso_ops = iso_drv->ops;

	struct sc_card_driver *openpgp_driver = sc_get_openpgp_driver();
	openpgp_driver->ops->init = pgp_modified_init;

	return openpgp_driver;
}

void *sc_module_init(const char *name)
{
	const char openpgp_modified_name[] = "openpgp-modified";
	if(name){
		if(strcmp(openpgp_modified_name, name) == 0)
		return sc_get_modified_openpgp_driver;
	}
	return NULL;
}

const char *sc_driver_version(void)
{
	return sc_get_version();
}
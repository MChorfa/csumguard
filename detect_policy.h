/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CSG_DETECT_POLICY_H
#define CSG_DETECT_POLICY_H
/* Pure predicate after safe CO-RE reads. CHECKSUM_PARTIAL is Linux value 3. */
static inline int csg_suspicious(unsigned state, unsigned vhl,
                                 unsigned network_header, unsigned start)
{
 unsigned ihl = (vhl & 15u) * 4;
 return state == 3 && (vhl >> 4) == 4 && ihl >= 20 &&
        network_header <= 0xffffu - ihl && start <= 0xffffu &&
        start < network_header + ihl;
}
#endif

// Copyright (c)  The Bitcoin Core developers
// Copyright (c) 2017 The Raven Core developers
// Copyright (c) 2018 The Rito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RITO_QT_RITOADDRESSVALIDATOR_H
#define RITO_QT_RITOADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class RitoAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit RitoAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** Rito address widget validator, checks for a valid rito address.
 */
class RitoAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit RitoAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // RITO_QT_RITOADDRESSVALIDATOR_H

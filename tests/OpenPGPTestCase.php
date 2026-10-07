<?php declare(strict_types=1);

namespace OpenPGP\Tests;

use Faker\Factory as FakerFactory;
use OpenPGP\Common\Armor;
use OpenPGP\Enum\{ArmorType, HashAlgorithm, KeyFlag, SignatureType};
use OpenPGP\Packet\{PacketList, Signature, UserID};
use OpenPGP\Packet\Signature\KeyFlags;
use OpenPGP\Type\PrivateKeyInterface;
use PHPUnit\Framework\TestCase;

/**
 * Base class for all OpenPGP test cases.
 */
abstract class OpenPGPTestCase extends TestCase
{
    protected $faker;

    protected function setUp(): void
    {
        $this->faker = FakerFactory::create();
    }

    /**
     * Armor the public part of a key, self-signed again with extra hashed subpackets
     * on its user certification and its subkey binding.
     */
    protected static function armorPublicKeyWithSelfSignatureSubpackets(
        PrivateKeyInterface $privateKey,
        array $subpackets
    ): string {
        $keyPacket = $privateKey->getKeyPacket();
        $subkeyPacket = $privateKey->getSubkeys()[0]->getKeyPacket();
        $userID = new UserID($privateKey->getUsers()[0]->getUserID());

        return Armor::encode(
            ArmorType::PublicKey,
            (new PacketList([
                $keyPacket->getPublicKey(),
                $userID,
                Signature::createSignature(
                    $keyPacket,
                    SignatureType::CertGeneric,
                    implode([
                        $keyPacket->getSignBytes(),
                        $userID->getSignBytes(),
                    ]),
                    HashAlgorithm::Sha256,
                    [
                        KeyFlags::fromFlags(
                            KeyFlag::CertifyKeys->value |
                                KeyFlag::SignData->value
                        ),
                        ...$subpackets,
                    ]
                ),
                $subkeyPacket->getPublicKey(),
                Signature::createSignature(
                    $keyPacket,
                    SignatureType::SubkeyBinding,
                    implode([
                        $keyPacket->getSignBytes(),
                        $subkeyPacket->getSignBytes(),
                    ]),
                    HashAlgorithm::Sha256,
                    [
                        KeyFlags::fromFlags(
                            KeyFlag::EncryptCommunication->value |
                                KeyFlag::EncryptStorage->value
                        ),
                        ...$subpackets,
                    ]
                ),
            ]))->encode()
        );
    }
}

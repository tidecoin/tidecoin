Translations
============

Tidecoin supports multiple localizations. For managing application translations,
the project uses the Transifex online translation management tool.

### Helping to translate (using Transifex)
Transifex is set up to monitor the GitHub repository for source-string updates.
After a pull request is merged, it may take several hours for new strings to
appear in Transifex.

Multiple language support is important for Tidecoin accessibility and global
use.

The Transifex mapping used by this repository is defined in [`.tx/config`](/.tx/config):

```ini
[o:tidecoin:p:tidecoin:r:qt-translation]
```

### Writing code with translations
We use automated scripts to extract translations in both Qt and non-Qt source
files. It is rarely necessary to manually edit files in `src/qt/locale/`.

Locale filenames in this repository use the Tidecoin namespace, for example:
`tidecoin_xx_YY.ts or tidecoin_xx.ts`

`src/qt/locale/tidecoin_en.ts` is treated specially as the source language file.
When source strings change, this file must be refreshed. The `translate` build
target uses `gettext`, `lupdate`, and `lconvert` to regenerate:
- `src/qt/tidecoinstrings.cpp`
- `src/qt/locale/tidecoin_en.ts`
- `src/qt/locale/tidecoin_en.xlf`

To automatically regenerate the `tidecoin_en.ts` file, run the following commands:
```sh
cmake -B build
cmake --build build --target translate
```

**Example Qt translation**
```cpp
QToolBar *toolbar = addToolBar(tr("Tabs toolbar"));
```

### Creating a pull-request
For general PRs, do not include broad translation refreshes unless your PR is
specifically about translation updates. This helps avoid translation merge
conflicts.

When updated source strings are merged, Transifex detects and queues them.
After processing, the strings appear as untranslated in the Transifex web UI.

For translation refresh PRs, stage the actual changed files, for example:
```
git add src/qt/tidecoinstrings.cpp src/qt/locale/*.ts src/qt/locale/tidecoin_en.xlf
git commit
```

### Creating a Transifex account
Visit the [Transifex Signup](https://app.transifex.com/signup/open-source/)
page to create an account.

### Installing the Transifex client command-line tool
The client is used to fetch updated translations. Installation instructions:
<https://developers.transifex.com/docs/cli>.

The Tidecoin Transifex project config is included in this repository at
`.tx/config`. In normal operation, you should not need to modify it.

### Synchronising translations

To synchronize translations for a release/update cycle:

1. Pull translations from the configured Tidecoin Transifex resource.
```
tx pull -f --translations --minimum-perc=1
```

2. Regenerate source-language artifacts.
```sh
cmake --build build --target translate
```

3. Review and commit the resulting locale changes.

**Do not download and commit translations one-by-one from the web UI.** Always
use the configured CLI workflow so changes are reproducible and reviewable.

### Handling Plurals (in source files)
When new plurals are added to the source file, it's important to do the following steps:

1. Open `tidecoin_en.ts` in Qt Linguist (included in the Qt SDK)
2. Search for `%n`, which will take you to the parts in the translation that use plurals
3. Look for empty `English Translation (Singular)` and `English Translation (Plural)` fields
4. Add the appropriate strings for the singular and plural form of the base string
5. Mark the item as done (via the green arrow symbol in the toolbar)
6. Repeat from step 2, until all singular and plural forms are in the source file
7. Save the source file

### Translating a new language
To create a new language template, you will need to edit the languages manifest file `src/qt/tidecoin_locale.qrc` and add a new entry. Below is an example of the English language entry.

```xml
<qresource prefix="/translations">
    <file alias="en">locale/tidecoin_en.qm</file>
    ...
</qresource>
```

**Note:** that the language translation file **must end in `.qm`** (the compiled extension), and not `.ts`.

### Questions and general assistance

For translator or process questions, open a GitHub issue in
<https://github.com/tidecoin/tidecoin>.

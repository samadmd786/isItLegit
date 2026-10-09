# Launch checklist

Challenge window closes **Sunday Oct 12, 2026, 1:00 PM PT (20:00 UTC)**. The
first 100 qualifying articles win credits, so earlier is better.

## 1. GitHub ✅ done: https://github.com/samadmd786/isItLegit

Either create an empty **public** repo named `isthislegit` at github.com/new
(no README or license), or fix the CLI:

```bash
unset GITHUB_TOKEN
gh auth login
gh repo create samadmd786/isItLegit --public --source . --push
```

If you created it on the website instead:

```bash
git remote add origin git@github.com:samadmd786/isItLegit.git
git push -u origin main
```

## 2. AWS deploy ✅ done: https://main.dp6j97gnjo03s.amplifyapp.com

1. In the IAM console (account 082492029366): Users → Create user →
   `isthislegit-deployer`, no console access. Choose **Attach policies
   directly → Create policy → JSON**, paste `docs/iam-deployer-policy.json`,
   name it `isthislegit-deploy`, and attach it.
2. Open the user → Security credentials → Create access key → "Command Line
   Interface". Then:

   ```bash
   aws configure --profile isthislegit-deployer    # region us-east-1, output json
   ```

3. Deploy:

   ```bash
   scripts/deploy.sh --profile isthislegit-deployer
   ```

4. Open the printed App URL in a private window. Try the four sample buttons,
   switch the language, and tap Read it to me.

Note: any user that can create a role and pass it to Lambda can, in
principle, give that Lambda more power than it has itself. Treat these keys
like admin keys, and delete the access key after the challenge.

## 3. Fill the placeholders

- [x] `ARTICLE.md`: Amplify URL (2 places)
- [x] `ARTICLE.md`: GitHub URL (2 places)
- [x] Parent quote: removed (decided Oct 9)
- [x] `README.md`: live demo link

## 4. Builder profile (required or the entry is invalid)

- [ ] Profile image
- [ ] Country
- [ ] About section filled in

## 5. Publish on Builder Center

- [ ] Paste the article. Upload the screenshots from `docs/screenshots/`,
      because relative image paths won't work there.
- [ ] Tag **#agents**
- [ ] Optional: a 15-second screen recording (paste toll text → DON'T CLICK
      → switch to Hindi → Read it to me) makes the strongest "proof it works".
- [ ] Publish, then drop the link in the challenge post's comments.

## After the challenge

```bash
scripts/destroy.sh --profile isthislegit-deployer    # removes Lambda, API, Amplify app, bucket
```
